#!/usr/bin/env python3
"""
SecureChat Server (assignment-ready).

Features:
- Mutual X.509 validation against certs/ca.cert.pem
- Two DH rounds: one ephemeral (K_temp) for register/login, one final (K) for chat
- AES-128(ECB)+PKCS7 encryption (app.crypto.aes)
- Per-message SHA256 digest signed with RSA (verify_signature)
- Replay protection via monotonic seqno
- Append-only transcript logging + signed session receipt
- Uses MySQL (Docker) per .env settings; will insert salt (VARBINARY) and pwd_hash (hex)
"""
import os
import socket
import threading
import json
import time
import base64
import hashlib
import hmac
from pathlib import Path
from datetime import datetime
from dotenv import load_dotenv

# crypto helpers (assumes these modules implemented earlier)
from app.crypto.pki import validate_cert_chain
from app.crypto.dh import gen_private_int, compute_shared_secret, derive_aes_key_from_ks
from app.crypto.aes import encrypt_aes_ecb, decrypt_aes_ecb, b64enc, b64dec
from app.crypto.sign import sign_bytes, verify_signature

# DB connector
import mysql.connector

# Load config from .env
ROOT = Path(__file__).resolve().parents[1]
load_dotenv(ROOT / ".env")

HOST = os.getenv("SERVER_HOST", "127.0.0.1")
PORT = int(os.getenv("SERVER_PORT", "9999"))
CERT_DIR = Path(os.getenv("CERT_DIR", "certs"))
CA_CERT_PATH = CERT_DIR / "ca.cert.pem"
SERVER_CERT_PATH = CERT_DIR / "server.cert.pem"
SERVER_KEY_PATH = CERT_DIR / "server.key.pem"

DB_HOST = os.getenv("DB_HOST", "127.0.0.1")
DB_PORT = int(os.getenv("DB_PORT", "3307"))
DB_USER = os.getenv("DB_USER", "scuser")
DB_PASS = os.getenv("DB_PASSWORD", "scpass")
DB_NAME = os.getenv("DB_NAME", "securechat")

TRANSCRIPT_DIR = Path(os.getenv("TRANSCRIPT_DIR", "transcripts"))
TRANSCRIPT_DIR.mkdir(exist_ok=True)

# Use same DH params as client (simple demonstration prime; can be replaced)
P_HEX = ("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
         "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
         "EF9519B3CD")  # demo/truncated; acceptable for lab
P = int(P_HEX, 16)
G = 2

# ---------- framing helpers ----------
def send_json(sock: socket.socket, obj: dict) -> None:
    sock.sendall((json.dumps(obj) + "\n").encode())

def recv_json(sock: socket.socket):
    f = sock.makefile("rb")
    line = f.readline()
    if not line:
        return None
    return json.loads(line.decode())

# ---------- DB helpers (direct SQL for predictable schema) ----------
def db_connect():
    return mysql.connector.connect(host=DB_HOST, port=DB_PORT, user=DB_USER, password=DB_PASS, database=DB_NAME)

def insert_user_with_salt(email: str, username: str, salt_bytes: bytes, pwd_hash_hex: str):
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("INSERT INTO users (email, username, salt, pwd_hash) VALUES (%s,%s,%s,%s)",
                (email, username, salt_bytes, pwd_hash_hex))
    conn.commit()
    cur.close()
    conn.close()

def get_user_record(email: str):
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("SELECT email, username, salt, pwd_hash FROM users WHERE email=%s", (email,))
    row = cur.fetchone()
    cur.close()
    conn.close()
    return row  # None or (email, username, salt_bytes, pwd_hash_hex)

# ---------- canonical hash input ----------
def make_hash_input(seqno: int, ts: int, ct_bytes: bytes) -> bytes:
    return seqno.to_bytes(8, "big") + ts.to_bytes(8, "big") + ct_bytes

# ---------- handler ----------
def handle_client(conn: socket.socket, addr):
    print(f"[+] Connection from {addr}")
    transcript_path = TRANSCRIPT_DIR / f"server_{int(time.time())}_{addr[1]}.log"
    last_seq = 0
    client_cert_pem = None

    try:
        # 1) Hello
        hello = recv_json(conn)
        if hello is None:
            print("[-] Empty hello"); conn.close(); return
        if hello.get("type") != "hello":
            send_json(conn, {"type":"error", "why":"BAD_HELLO"}); conn.close(); return

        client_cert_pem = hello.get("client_cert", "").encode()
        if not client_cert_pem:
            send_json(conn, {"type":"error", "why":"NO_CLIENT_CERT"}); conn.close(); return

        ok, reason = validate_cert_chain(client_cert_pem)
        if not ok:
            send_json(conn, {"type":"error", "why":"BAD_CERT", "detail": reason}); conn.close(); return
        print("[+] Client cert validated")

        # send server hello (server cert)
        server_cert_pem = open(SERVER_CERT_PATH, "rb").read().decode()
        send_json(conn, {"type":"server_hello", "server_cert": server_cert_pem})

        # 2) Ephemeral DH (K_temp) for register/login
        dh_msg = recv_json(conn)
        if dh_msg is None or dh_msg.get("type") != "dh_client":
            send_json(conn, {"type":"error", "why":"EXPECTED_DH_CLIENT"}); conn.close(); return
        p = int(dh_msg["p"]); g = int(dh_msg["g"]); A = int(dh_msg["A"])
        b = gen_private_int()
        B = pow(g, b, p)
        send_json(conn, {"type":"dh_server", "B": str(B)})
        ks = compute_shared_secret(A, b, p)
        K_temp = derive_aes_key_from_ks(ks)
        print("[+] Derived K_temp (for register/login)")

        # 3) Encrypted register/login payload
        enc_msg = recv_json(conn)
        if enc_msg is None or "ct" not in enc_msg:
            send_json(conn, {"type":"error", "why":"NO_ENC_PAYLOAD"}); conn.close(); return
        ct_b64 = enc_msg["ct"]
        try:
            ct = b64dec(ct_b64)
            pt = decrypt_aes_ecb(K_temp, ct)
            payload = json.loads(pt.decode())
        except Exception as e:
            send_json(conn, {"type":"error", "why":"DECRYPT_FAIL", "detail": str(e)}); conn.close(); return

        # payload handling: support both client-supplied salt+pwd_hash OR plaintext password
        if payload.get("type") == "register":
            email = payload.get("email"); username = payload.get("username")
            if not (email and username):
                send_json(conn, {"type":"register_resp", "ok": False, "reason": "MISSING_FIELDS"}); conn.close(); return

            # Two possible payload shapes:
            # A) client provided 'salt' (base64) and 'pwd_hash' (base64 of raw digest)
            # B) client provided 'password' (plaintext) -> server must create salt and compute hash
            if "salt" in payload and "pwd_hash" in payload:
                salt = base64.b64decode(payload["salt"])
                pwd_hash_raw = base64.b64decode(payload["pwd_hash"])  # raw digest bytes
                pwd_hash_hex = pwd_hash_raw.hex()
            elif "password" in payload:
                salt = os.urandom(16)
                pwd_hash_raw = hashlib.sha256(salt + payload["password"].encode()).digest()
                pwd_hash_hex = pwd_hash_raw.hex()
            else:
                send_json(conn, {"type":"register_resp", "ok": False, "reason":"BAD_PAYLOAD"}); conn.close(); return

            # insert into DB
            try:
                insert_user_with_salt(email, username, salt, pwd_hash_hex)
            except mysql.connector.IntegrityError as ie:
                send_json(conn, {"type":"register_resp", "ok": False, "reason":"exists"})
                # do not close immediately so client can choose login
                return
            except Exception as e:
                send_json(conn, {"type":"register_resp", "ok": False, "reason": str(e)}); conn.close(); return

            send_json(conn, {"type":"register_resp", "ok": True})
            print(f"[+] Registered new user {email}")

        elif payload.get("type") == "login":
            email = payload.get("email")
            if not email:
                send_json(conn, {"type":"login_resp", "ok": False, "reason":"MISSING_EMAIL"}); conn.close(); return

            # Expect client sends 'pwd_hash' as base64(raw_digest) where raw_digest = SHA256(salt||password)
            if "pwd_hash" not in payload:
                send_json(conn, {"type":"login_resp", "ok": False, "reason":"MISSING_PWD_HASH"}); conn.close(); return

            rec = get_user_record(email)
            if not rec:
                send_json(conn, {"type":"login_resp", "ok": False, "reason":"NO_USER"}); conn.close(); return
            _, username, salt_bytes, stored_hash_hex = rec
            # compute expected hex from client's posted base64 raw digest
            try:
                client_raw_digest = base64.b64decode(payload["pwd_hash"])
                client_hex = client_raw_digest.hex()
            except Exception:
                send_json(conn, {"type":"login_resp", "ok": False, "reason":"BAD_PWD_HASH"}); conn.close(); return

            # constant-time compare
            if not hmac.compare_digest(client_hex, stored_hash_hex):
                send_json(conn, {"type":"login_resp", "ok": False, "reason":"AUTH_FAIL"}); conn.close(); return

            send_json(conn, {"type":"login_resp", "ok": True})
            print(f"[+] Login OK for {email}")

        else:
            send_json(conn, {"type":"error", "why":"UNKNOWN_PAYLOAD_TYPE"}); conn.close(); return

        # 4) Post-auth DH for session key
        dh2 = recv_json(conn)
        if dh2 is None or dh2.get("type") != "dh_client":
            send_json(conn, {"type":"error", "why":"EXPECTED_DH_CLIENT_2"}); conn.close(); return
        p2 = int(dh2["p"]); g2 = int(dh2["g"]); A2 = int(dh2["A"])
        b2 = gen_private_int()
        B2 = pow(g2, b2, p2)
        send_json(conn, {"type":"dh_server", "B": str(B2)})
        ks2 = compute_shared_secret(A2, b2, p2)
        K = derive_aes_key_from_ks(ks2)
        print("[+] Session key established for chat")

        # prepare server signing key and transcript
        server_key_pem = open(SERVER_KEY_PATH, "rb").read()
        transcript_path = TRANSCRIPT_DIR / f"server_{int(time.time())}_{addr[1]}.log"
        peer_cert_fp = hashlib.sha256(client_cert_pem).hexdigest()

        # message loop
        last_seq = 0
        while True:
            obj = recv_json(conn)
            if obj is None:
                print("[*] Client disconnected")
                break
            if obj.get("type") == "msg":
                seq = int(obj["seqno"]); ts = int(obj["ts"]); ct_b64 = obj["ct"]; sig_b64 = obj["sig"]
                # replay check
                if seq <= last_seq:
                    send_json(conn, {"type":"error", "why":"REPLAY"}); print("REPLAY"); continue
                # verify signature (signature is base64 string)
                ct_bytes = base64.b64decode(ct_b64)
                digest = hashlib.sha256(make_hash_input(seq, ts, ct_bytes)).digest()
                # verify using client's cert bytes
                ok = verify_signature(client_cert_pem, sig_b64, digest)
                if not ok:
                    send_json(conn, {"type":"error", "why":"SIG_FAIL"}); print("SIG_FAIL"); continue
                # decrypt
                try:
                    pt = decrypt_aes_ecb(K, ct_bytes)
                except Exception as e:
                    send_json(conn, {"type":"error", "why":"DECRYPT_FAIL", "detail": str(e)}); continue
                print(f"[peer {addr}] {pt.decode()}")
                # append transcript
                with open(transcript_path, "ab") as tf:
                    tf.write(f"{seq}|{ts}|{ct_b64}|{sig_b64}|{peer_cert_fp}\n".encode())
                last_seq = seq

            elif obj.get("type") == "receipt_request":
                # produce receipt
                if not transcript_path.exists():
                    send_json(conn, {"type":"error", "why":"NO_TRANSCRIPT"}); continue
                whole = transcript_path.read_bytes()
                thash = hashlib.sha256(whole).hexdigest()
                sig = sign_bytes(server_key_pem, thash.encode())
                receipt = {"type":"receipt", "first_seq":1, "last_seq": last_seq, "transcript_sha256": thash, "sig": sig}
                # persist receipt file
                open(str(transcript_path) + ".receipt.server.json", "w").write(json.dumps(receipt, indent=2))
                send_json(conn, {"type":"receipt", "receipt": receipt})
            else:
                send_json(conn, {"type":"error", "why":"UNKNOWN_TYPE"})

    except Exception as e:
        print("Handler exception:", e)
    finally:
        try: conn.close()
        except: pass
        print(f"Connection {addr} closed")

# ---------- server startup ----------
def start():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen(5)
    print(f"[SERVER] Listening on {HOST}:{PORT}")
    while True:
        conn, addr = s.accept()
        threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

if __name__ == "__main__":
    start()
