# app/crypto/sign.py
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
import base64

def sign_bytes(private_key_pem: bytes, data: bytes) -> str:
    priv = serialization.load_pem_private_key(private_key_pem, password=None)
    sig = priv.sign(
        data,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return base64.b64encode(sig).decode()

def verify_signature(pub_cert_pem: bytes, signature_b64: str, data: bytes) -> bool:
    from cryptography import x509
    cert = x509.load_pem_x509_certificate(pub_cert_pem)
    pub = cert.public_key()
    sig = base64.b64decode(signature_b64)
    try:
        pub.verify(sig, data, padding.PKCS1v15(), hashes.SHA256())
        return True
    except Exception:
        return False
