#!/usr/bin/env python3
"""
SecureChat client (assignment-ready).

Features:
- newline-delimited JSON framing (send_json/recv_json)
- mutual X.509 certificate validation against certs/ca.cert.pem
- ephemeral DH for protecting register/login payload
- post-auth DH for session key
- AES-128(ECB)+PKCS7 for encryption (app.crypto.aes)
- per-message SHA256 digest signed with RSA (app.crypto.sign)
- transcript logging and signed session receipt
- local storage of salts after registration (transcripts/salts.json)

Run:
  source .venv/bin/activate
  python -m app.client
"""
import socket
import json
import os
import time
import hashlib
import base64
from pathlib import Path
from dotenv import load_dotenv

# Crypto helpers (make sure these modules are available from earlier work)
from app.crypto.pki import validate_cert_chain
from app.crypto.dh import gen_private_int, compute_shared_secret, derive_aes_key_from_ks
from app.crypto.aes import encrypt_aes_ecb, decrypt_aes_ecb, b64enc, b64dec
from app.crypto.sign import sign_bytes

# --- Config / paths ---
ROOT = Path(__file__).resolve().parents[1]
load_dotenv(ROOT / ".env")

SERVER_HOST = os.getenv("SERVER_HOST", "127.0.0.1")
SERVER_PORT = int(os.getenv("SERVER_PORT", "9999"))
CERT_DIR = Path(os.getenv("CERT_DIR", "certs"))
CA_CERT_PATH = CERT_DIR / "ca.cert.pem"
CLIENT_CERT_PATH = CERT_DIR / "client.cert.pem"
CLIENT_KEY_PATH = CERT_DIR / "client.key.pem"

TRANSCRIPT_DIR = Path(os.getenv("TRANSCRIPT_DIR", "transcripts"))
TRANSCRIPT_DIR.mkdir(exist_ok=True)

SALTS_FILE = TRANSCRIPT_DIR / "salts.json"  # local storage for salts after register

# Use a large safe-ish prime (shortened example replaced by previously used number)
P_HEX = ("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
         "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
         "EF9519B3CD")  # truncated demo prime; for real use use RFC7919 groups
P = int(P_HEX, 16)
G = 2

# --- Framing helpers ---
def send_json(sock: socket.socket, obj: dict) -> None:
    sock.sendall((json.dumps(obj) + "\n").encode())

def recv_json(sock: socket.socket):
    fileobj = sock.makefile("rb")
    line = fileobj.readline()
    if not line:
        return None
    return json.loads(line.decode())

# --- Utility helpers ---
def now_ms() -> int:
    return int(time.time() * 1000)

def load_salts() -> dict:
    if SALTS_FILE.exists():
        try:
            return json.loads(SALTS_FILE.read_text())
        except Exception:
            return {}
    return {}

def save_salts(d: dict):
    SALTS_FILE.write_text(json.dumps(d, indent=2))

def make_digest(seqno: int, ts: int, ct_bytes: bytes) -> bytes:
    # consistent digest input: seq (8 bytes BE) | ts (8 bytes BE) | ct
    return seqno.to_bytes(8, "big") + ts.to_bytes(8, "big") + ct_bytes

# --- Main client flow ---
def run():
    # Connect
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((SERVER_HOST, SERVER_PORT))
    except ConnectionRefusedError:
        print(f"[!] Connection refused: is server running on {SERVER_HOST}:{SERVER_PORT}?")
        return

    # Send hello (client cert)
    client_cert_pem = open(CLIENT_CERT_PATH, "rb").read().decode()
    send_json(sock, {"type": "hello", "client_cert": client_cert_pem, "nonce": base64.b64encode(os.urandom(8)).decode()})

    # Receive server hello & validate server cert
    srv = recv_json(sock)
    if srv is None:
        print("[!] Server closed connection unexpectedly.")
        sock.close(); return
    if srv.get("type") == "error":
        print("[!] Server error:", srv.get("why")); sock.close(); return
    server_cert_pem = srv.get("server_cert", "").encode()
    ok, reason = validate_cert_chain(server_cert_pem)
    if not ok:
        print("[!] Server certificate validation FAILED:", reason)
        sock.close(); return
    print("[+] Server certificate validated")

    # === Temporary DH for protecting register/login ===
    a = gen_private_int()
    A = pow(G, a, P)
    send_json(sock, {"type": "dh_client", "p": str(P), "g": str(G), "A": str(A)})
    dh_resp = recv_json(sock)
    if dh_resp is None or dh_resp.get("type") == "error":
        print("[!] DH server error or closed"); sock.close(); return
    B = int(dh_resp["B"])
    ks = compute_shared_secret(B, a, P)
    K_temp = derive_aes_key_from_ks(ks)
    print("[+] Temporary DH established (for register/login)")

    # choose action
    action = input("Choose action: [r]egister / [l]ogin: ").strip().lower()
    salts = load_salts()

    if action == "r":
        email = input("email: ").strip()
        username = input("username: ").strip()
        password = input("password: ").strip()  # getpass could be used but keep simple
        # client creates salt and computes salted hash locally (server also stores)
        salt = os.urandom(16)
        pwd_hash = hashlib.sha256(salt + password.encode()).digest()
        payload = {"type": "register", "email": email, "username": username,
                   "salt": base64.b64encode(salt).decode(), "pwd_hash": base64.b64encode(pwd_hash).decode()}
        enc = encrypt_aes_ecb(K_temp, json.dumps(payload).encode())
        send_json(sock, {"type": "enc", "ct": b64enc(enc)})
        resp = recv_json(sock)
        print("[*] Server:", resp)
        if resp and resp.get("type") == "ok":
            # store salt locally for future login
            salts[email] = base64.b64encode(salt).decode()
            save_salts(salts)
            print("[+] Registration OK — saved salt locally.")
        sock.close(); return

    elif action == "l":
        email = input("email: ").strip()
        if email not in salts:
            print("[!] No salt found locally for this email. Provide salt (base64) or register first.")
            salt_b64 = input("salt (base64, blank to abort): ").strip()
            if not salt_b64:
                print("Aborting."); sock.close(); return
            salts[email] = salt_b64
            save_salts(salts)
        salt = base64.b64decode(salts[email])
        password = input("password: ").strip()
        pwd_hash = hashlib.sha256(salt + password.encode()).digest()
        payload = {"type": "login", "email": email, "pwd_hash": base64.b64encode(pwd_hash).decode()}
        enc = encrypt_aes_ecb(K_temp, json.dumps(payload).encode())
        send_json(sock, {"type": "enc", "ct": b64enc(enc)})
        resp = recv_json(sock)
        print("[*] Login response:", resp)
        if not resp or resp.get("type") != "ok":
            sock.close(); return
        # else continue to post-auth session
    else:
        print("Unknown action"); sock.close(); return

    # === Post-auth DH for session key (fresh key for chat) ===
    a2 = gen_private_int()
    A2 = pow(G, a2, P)
    send_json(sock, {"type": "dh_client", "p": str(P), "g": str(G), "A": str(A2)})
    dh2 = recv_json(sock)
    if dh2 is None or dh2.get("type") == "error":
        print("[!] Post-auth DH failed"); sock.close(); return
    B2 = int(dh2["B"])
    ks2 = compute_shared_secret(B2, a2, P)
    K = derive_aes_key_from_ks(ks2)
    print("[+] Session key established (16-byte AES key)")

    # Prepare transcript and receipt
    transcript_path = TRANSCRIPT_DIR / f"client_{int(time.time())}.log"
    receipt_path = TRANSCRIPT_DIR / f"receipt_client_{int(time.time())}.json"
    seqno = 0

    # load own private key bytes for signing
    priv_pem = open(CLIENT_KEY_PATH, "rb").read()

    try:
        while True:
            line = input("you> ")
            if not line:
                continue
            if line.strip().lower() in ("/quit", "/exit"):
                print("[*] Quitting")
                break

            seqno += 1
            ts = now_ms()
            ct = encrypt_aes_ecb(K, line.encode())
            ct_b64 = b64enc(ct)
            digest_input = make_digest = make_digest = seqno.to_bytes(8, "big") + ts.to_bytes(8, "big") + ct
            # sign digest bytes
            sig_b64 = sign_bytes(priv_pem, hashlib.sha256(digest_input).digest())

            # send message
            send_json(sock, {"type": "msg", "seqno": seqno, "ts": ts, "ct": ct_b64, "sig": sig_b64})

            # append to local transcript
            with open(transcript_path, "a") as tf:
                tf.write(f"{seqno}|{ts}|{ct_b64}|{sig_b64}\n")

            # non-blocking read for server error response (SIG_FAIL/REPLAY)
            resp = recv_json(sock)
            if resp:
                if resp.get("type") == "error":
                    print("[server error]", resp)

    except KeyboardInterrupt:
        pass
    finally:
        # produce signed session receipt
        if transcript_path.exists():
            txt = transcript_path.read_bytes()
            th = hashlib.sha256(txt).hexdigest()
            sig_receipt = sign_bytes(priv_pem, th.encode())
            receipt = {"type": "receipt", "client": True, "last_seq": seqno,
                       "transcript_sha256": th, "sig": sig_receipt}
            receipt_path.write_text(json.dumps(receipt, indent=2))
            print("[+] Session receipt written:", receipt_path)

        sock.close()

if __name__ == "__main__":
    run()
