# app/server.py
"""
Simple SecureChat server (application-layer crypto).
- Uses newline-terminated JSON for framing (send_json / recv_json).
- Steps: receive hello (client cert), validate cert, do DH exchange,
  receive AES-encrypted register/login payload, process, and reply.
Note: This is a teaching/demo server: adapt for your skeleton as needed.
"""
import socket
import threading
import json
import os
from pathlib import Path
import mysql.connector
from dotenv import load_dotenv
from app.crypto.pki import validate_cert_chain
from app.crypto.dh import gen_private_int, compute_shared_secret, derive_aes_key_from_ks
from app.crypto.aes import encrypt_aes_ecb, decrypt_aes_ecb, b64enc, b64dec

# Load env
ROOT = Path(__file__).resolve().parents[1]
load_dotenv(ROOT / ".env")

HOST = os.getenv("SERVER_HOST", "127.0.0.1")
PORT = int(os.getenv("SERVER_PORT", "9999"))
CERT_DIR = Path(os.getenv("CERT_DIR", "certs"))
SERVER_CERT = CERT_DIR / "server.cert.pem"
SERVER_KEY = CERT_DIR / "server.key.pem"

DB_HOST = os.getenv("DB_HOST", "127.0.0.1")
DB_PORT = int(os.getenv("DB_PORT", "3307"))
DB_USER = os.getenv("DB_USER", "scuser")
DB_PASS = os.getenv("DB_PASSWORD", "scpass")
DB_NAME = os.getenv("DB_NAME", "securechat")

def send_json(sock: socket.socket, obj: dict) -> None:
    data = (json.dumps(obj) + "\n").encode()
    sock.sendall(data)

def recv_json(sock: socket.socket):
    # Use makefile to read a full line (newline-terminated)
    fileobj = sock.makefile("rb")
    line = fileobj.readline()
    if not line:
        return None
    return json.loads(line.decode())

def handle_client(conn: socket.socket, addr):
    print(f"[+] New connection from {addr}")
    try:
        hello = recv_json(conn)
        if hello is None:
            print("[-] client closed connection without saying hello")
            conn.close()
            return

        client_cert_pem = hello.get("client_cert", "")
        if isinstance(client_cert_pem, str):
            client_cert_pem = client_cert_pem.encode()

        ok, reason = validate_cert_chain(client_cert_pem)
        if not ok:
            send_json(conn, {"type": "error", "why": "BAD_CERT", "detail": reason})
            print("[-] Rejected client cert:", reason)
            conn.close()
            return
        print("[+] Client cert validation:", reason)

        # Send server hello (send server cert)
        server_cert_pem = open(SERVER_CERT, "rb").read().decode()
        send_json(conn, {"type": "server_hello", "server_cert": server_cert_pem, "nonce": hello.get("nonce")})

        # Do DH key agreement
        dh_client = recv_json(conn)
        if dh_client is None or dh_client.get("type") != "dh_client":
            print("[-] Unexpected DH client message or connection closed")
            conn.close(); return
        p = int(dh_client["p"])
        g = int(dh_client["g"])
        A = int(dh_client["A"])
        b = gen_private_int()
        B = pow(g, b, p)
        send_json(conn, {"type": "dh_server", "B": str(B)})

        ks = compute_shared_secret(A, b, p)
        K = derive_aes_key_from_ks(ks)
        print("[+] Derived session AES key (16 bytes)")

        # Now expect encrypted payload (register/login)
        payload_msg = recv_json(conn)
        if payload_msg is None:
            print("[-] Connection closed before encrypted payload")
            conn.close(); return

        if payload_msg.get("type") not in ("register", "login"):
            send_json(conn, {"type": "error", "why": "bad_request"})
            conn.close(); return

        ct_b64 = payload_msg.get("ct")
        if ct_b64 is None:
            send_json(conn, {"type": "error", "why": "missing_ciphertext"})
            conn.close(); return

        try:
            ct = b64dec(ct_b64)
            pt = decrypt_aes_ecb(K, ct)
            pdata = json.loads(pt.decode())
        except Exception as e:
            send_json(conn, {"type": "error", "why": "decrypt_fail", "detail": str(e)})
            conn.close(); return

        # Simple registration: store user in DB
        if payload_msg["type"] == "register":
            email = pdata.get("email")
            username = pdata.get("username")
            password = pdata.get("password")
            if not (email and username and password):
                send_json(conn, {"type": "error", "why": "bad_payload"})
                conn.close(); return

            # Insert into DB (salt & hash logic assumed in app.storage.db; quick insert here)
            try:
                conn_db = mysql.connector.connect(host=DB_HOST, port=DB_PORT,
                                                  user="root", password=os.getenv("DB_ROOT_PASS","rootpass"))
                cur = conn_db.cursor()
                cur.execute(f"CREATE DATABASE IF NOT EXISTS {DB_NAME}")
                conn_db.commit()
                cur.close()
                conn_db.close()
            except Exception:
                # DB might already be prepared by init script; proceed to use scuser
                pass

            try:
                conn_db = mysql.connector.connect(host=DB_HOST, port=DB_PORT,
                                                  user=DB_USER, password=DB_PASS, database=DB_NAME)
                cur = conn_db.cursor()
                # Simple storage: store raw password? (not ideal). For real assignment use salted SHA256 as in storage/db.py
                # Here we insert only if not exists
                cur.execute("SELECT email FROM users WHERE email=%s", (email,))
                if cur.fetchone():
                    send_json(conn, {"type":"error", "why":"exists"})
                else:
                    # Use salted hash logic from storage/db.py if available; we store placeholder salt/hash
                    import secrets, hashlib
                    salt = secrets.token_bytes(16)
                    pwd_hash = hashlib.sha256(salt + password.encode()).hexdigest()
                    cur.execute("INSERT INTO users (email, username, salt, pwd_hash) VALUES (%s,%s,%s,%s)",
                                (email, username, salt, pwd_hash))
                    conn_db.commit()
                    send_json(conn, {"type":"ok", "status":"registered"})
                cur.close()
                conn_db.close()
            except Exception as e:
                send_json(conn, {"type":"error", "why":"db_error", "detail": str(e)})
                conn.close(); return

        elif payload_msg["type"] == "login":
            # Very similar pattern: verify credentials
            email = pdata.get("email"); password = pdata.get("password")
            try:
                conn_db = mysql.connector.connect(host=DB_HOST, port=DB_PORT,
                                                  user=DB_USER, password=DB_PASS, database=DB_NAME)
                cur = conn_db.cursor()
                cur.execute("SELECT salt,pwd_hash FROM users WHERE email=%s", (email,))
                row = cur.fetchone()
                if not row:
                    send_json(conn, {"type":"error","why":"no_user"})
                else:
                    salt, stored_hash = row
                    import hashlib
                    if hashlib.sha256(salt + password.encode()).hexdigest() == stored_hash:
                        send_json(conn, {"type":"ok","status":"login_ok"})
                    else:
                        send_json(conn, {"type":"error","why":"bad_creds"})
                cur.close(); conn_db.close()
            except Exception as e:
                send_json(conn, {"type":"error","why":"db_error","detail":str(e)})
                conn.close(); return

        print("[+] Finished handling client, closing connection")
        conn.close()
    except Exception as exc:
        print("Exception in handler:", exc)
        try: conn.close()
        except Exception: pass

def main():
    print(f"Starting server on {HOST}:{PORT}")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((HOST, PORT))
    sock.listen(5)
    try:
        while True:
            conn, addr = sock.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()
    except KeyboardInterrupt:
        print("Server shutting down")
    finally:
        sock.close()

if __name__ == "__main__":
    main()
