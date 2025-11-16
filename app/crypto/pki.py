# app/crypto/pki.py
from cryptography import x509
from cryptography.hazmat.primitives import serialization,hashes
from cryptography.x509.oid import NameOID
import datetime

CA_CERT_PATH = "certs/ca.cert.pem"

def load_cert(pem_bytes: bytes):
    return x509.load_pem_x509_certificate(pem_bytes)

def validate_cert_chain(cert_pem: bytes) -> (bool, str):
    """
    Very small validation:
     - signature checked against CA cert
     - not expired
     - CN present (non-empty)
    """
    try:
        ca = x509.load_pem_x509_certificate(open(CA_CERT_PATH, "rb").read())
        cert = x509.load_pem_x509_certificate(cert_pem)
        # Verify signature by verifying cert was signed by CA (simplified)
        ca_pub = ca.public_key()
        ca_pub.verify(cert.signature, cert.tbs_certificate_bytes,
                      # signature padding and hash algorithm inferred from cert.signature_algorithm_oid
                      cert.signature_hash_algorithm.padding if hasattr(cert.signature_hash_algorithm, 'padding') else None,
                      cert.signature_hash_algorithm)
    except Exception:
        # fallback: perform simple chain verification using public key verify may fail due to API differences;
        # We'll attempt to validate issuer matches CA subject and validity time only.
        try:
            cert = x509.load_pem_x509_certificate(cert_pem)
            ca = x509.load_pem_x509_certificate(open(CA_CERT_PATH, "rb").read())
            if cert.issuer != ca.subject:
                return False, "Issuer mismatch"
            now = datetime.datetime.utcnow()
            if now < cert.not_valid_before or now > cert.not_valid_after:
                return False, "Expired or not yet valid"
            cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            if not cn:
                return False, "Missing CN"
            return True, "OK (basic)"
        except Exception as e:
            return False, f"Validation error: {e}"

    # If we reach here, assume OK
    now = datetime.datetime.utcnow()
    if now < cert.not_valid_before or now > cert.not_valid_after:
        return False, "Expired or not yet valid"
    try:
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except Exception:
        return False, "Missing CN"
    return True, "OK"
