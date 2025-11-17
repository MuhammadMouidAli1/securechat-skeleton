# app/client.py
"""
Simple SecureChat client (application-layer crypto).
- Uses newline-terminated JSON framing (send_json / recv_json).
- Demonstrates: send hello (client cert), DH, then AES-encrypted register payload.
"""
import socket
import json
import os
from pathlib import Path
from dotenv import load_dotenv
from app.crypto.pki import validate_cert_chain
from app.crypto.dh import gen_private_int, derive_aes_key_from_ks, compute_shared_secret
from app.crypto.aes import encrypt_aes_ecb, decrypt_aes_ecb, b64enc, b64dec

# Load env
ROOT = Path(__file__).resolve().parents[1]
load_dotenv(ROOT / ".env")

HOST = os.getenv("SERVER_HOST", "127.0.0.1")
PORT = int(os.getenv("SERVER_PORT", "9999"))
CERT_DIR = Path(os.getenv("CERT_DIR", "certs"))
CLIENT_CERT = CERT_DIR / "client.cert.pem"
CLIENT_KEY = CERT_DIR / "client.key.pem"

def send_json(sock: socket.socket, obj: dict) -> None:
    data = (json.dumps(obj) + "\n").encode()
    sock.sendall(data)

def recv_json(sock: socket.socket):
    fileobj = sock.makefile("rb")
    line = fileobj.readline()
    if not line:
        return None
    return json.loads(line.decode())

def main():
    s = socket.socket()
    try:
        s.connect((HOST, PORT))
    except ConnectionRefusedError:
        print("Connection refused: is the server running on", HOST, PORT)
        return

    # Send hello with client cert
    client_cert_pem = open(CLIENT_CERT, "rb").read().decode()
    send_json(s, {"type":"hello", "client_cert": client_cert_pem, "nonce": "nonce-1"})

    # Receive server hello
    sh = recv_json(s)
    if sh is None:
        print("Server closed connection or sent empty reply")
        s.close(); return
    server_cert_pem = sh.get("server_cert", "").encode()
    ok, reason = validate_cert_chain(server_cert_pem)
    if not ok:
        print("Server certificate validation failed:", reason)
        s.close(); return
    print("[+] Server cert validated:", reason)

    # DH: choose p,g and do classic DH
    # For demo purposes use a safe-ish prime (you may use RFC7919 params in real code)
    p = int("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1", 16)
    g = 2
    a = gen_private_int()
    A = pow(g, a, p)
    send_json(s, {"type":"dh_client", "p": str(p), "g": str(g), "A": str(A)})

    dh_server = recv_json(s)
    if dh_server is None or dh_server.get("type") != "dh_server":
        print("[-] No DH server response or connection closed")
        s.close(); return

    B = int(dh_server["B"])
    ks = compute_shared_secret(B, a, p)
    K = derive_aes_key_from_ks(ks)
    print("[+] Derived session AES key (16 bytes)")

    # Example: send a registration payload encrypted with AES-128(ECB)+PKCS7
    reg = {"email":"alice@example.com", "username":"alice", "password":"s3cret"}
    ct = encrypt_aes_ecb(K, json.dumps(reg).encode())
    send_json(s, {"type":"register", "ct": b64enc(ct)})

    # Read server response
    resp = recv_json(s)
    if resp is None:
        print("[-] Server closed connection before replying")
        s.close(); return
    print("[+] Server replied:", resp)

    s.close()

if __name__ == "__main__":
    main()
