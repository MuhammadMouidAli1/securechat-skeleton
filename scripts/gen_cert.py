#!/usr/bin/env python3
# scripts/gen_cert.py
import argparse
from pathlib import Path
from cryptography.hazmat.primitives import serialization,hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
import datetime

ROOT = Path(__file__).resolve().parents[1]
CERT_DIR = ROOT / "certs"
CA_KEY = CERT_DIR / "ca.key.pem"
CA_CERT = CERT_DIR / "ca.cert.pem"

def main(cn, out_prefix):
    ca_key = serialization.load_pem_private_key(open(CA_KEY,"rb").read(), password=None)
    ca_cert = x509.load_pem_x509_certificate(open(CA_CERT,"rb").read())

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"PK"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Student"),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])
    cert = (x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(minutes=1))
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )

    open(CERT_DIR / f"{out_prefix}.key.pem", "wb").write(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ))
    open(CERT_DIR / f"{out_prefix}.cert.pem", "wb").write(cert.public_bytes(serialization.Encoding.PEM))
    print("Wrote:", CERT_DIR / f"{out_prefix}.key.pem", CERT_DIR / f"{out_prefix}.cert.pem")

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--cn", required=True)
    p.add_argument("--out", required=True)
    args = p.parse_args()
    main(args.cn, args.out)
