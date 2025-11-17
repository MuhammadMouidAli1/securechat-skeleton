# app/crypto/pki.py
"""
PKI helpers: load cert, validate certificate using the local Root CA (certs/ca.cert.pem).
This verifies:
 - certificate signature by CA
 - validity period (not_before / not_after)
 - presence of a Common Name (CN)
"""
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509.oid import NameOID
from pathlib import Path
import datetime

CA_CERT_PATH = Path("certs") / "ca.cert.pem"

def load_cert(pem_bytes: bytes) -> x509.Certificate:
    return x509.load_pem_x509_certificate(pem_bytes)

def validate_cert_chain(cert_pem: bytes):
    """
    Returns (True, "OK") on success, otherwise (False, reason).
    Uses CA cert at certs/ca.cert.pem to verify signature and checks validity and CN.
    """
    try:
        ca_p = CA_CERT_PATH
        if not ca_p.exists():
            return False, f"CA cert not found at {ca_p}"
        ca_cert = x509.load_pem_x509_certificate(ca_p.read_bytes())
        cert = x509.load_pem_x509_certificate(cert_pem)

        # 1) Check validity period (use UTC aware)
        now = datetime.datetime.utcnow()
        if now < cert.not_valid_before.replace(tzinfo=None) or now > cert.not_valid_after.replace(tzinfo=None):
            return False, "Expired or not yet valid"

        # 2) Ensure CN exists and non-empty
        try:
            cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            if not cn:
                return False, "Missing CN"
        except Exception:
            return False, "Missing CN"

        # 3) Verify certificate signature using CA public key
        ca_pub = ca_cert.public_key()
        try:
            # Determine signature algorithm - assume RSA for our CA certs
            ca_pub.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm,
            )
        except Exception as e:
            return False, f"Signature verification failed: {e}"

        # 4) Finally, verify issuer matches CA subject
        if cert.issuer != ca_cert.subject:
            return False, "Issuer mismatch"

        return True, "OK"
    except Exception as e:
        return False, f"Validation error: {e}"
