#!/usr/bin/env python3
# scripts/gen_ca.py
import argparse
from pathlib import Path
from cryptography.hazmat.primitives import serialization,hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
import datetime

ROOT = Path(__file__).resolve().parents[1]
CERT_DIR = ROOT / "certs"
CERT_DIR.mkdir(parents=True, exist_ok=True)

def main(name):
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"PK"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, name),
        x509.NameAttribute(NameOID.COMMON_NAME, name + " Root CA"),
    ])
    cert = (x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(minutes=1))
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    open(CERT_DIR / "ca.key.pem", "wb").write(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ))
    open(CERT_DIR / "ca.cert.pem", "wb").write(cert.public_bytes(serialization.Encoding.PEM))
    print("Wrote ca.key.pem and ca.cert.pem in certs/")

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--name", default="FAST-NU Root CA")
    args = p.parse_args()
    main(args.name)
