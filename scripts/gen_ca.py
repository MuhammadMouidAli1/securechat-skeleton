#!/usr/bin/env python3
"""
Create a self-signed root CA and save key+cert to certs/ca.key.pem & certs/ca.cert.pem
"""
import argparse
from pathlib import Path
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
import datetime

CERT_DIR = Path(__file__).resolve().parent.parent / "certs"
CERT_DIR.mkdir(parents=True, exist_ok=True)

def main(name):
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"PK"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, name),
        x509.NameAttribute(NameOID.COMMON_NAME, name + " Root CA"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )

    # Write private key and cert
    (CERT_DIR / "ca.key.pem").write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    (CERT_DIR / "ca.cert.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    print("Wrote:", CERT_DIR / "ca.key.pem", CERT_DIR / "ca.cert.pem")

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--name", default="FAST-NU Root CA")
    args = p.parse_args()
    main(args.name)
