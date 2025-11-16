# app/crypto/dh.py
import secrets
from hashlib import sha256

# Use RFC 7919-like safe prime or small built-in parameters; skeleton expects int p,g passed in JSON
# Provide helper to compute key and truncation
def compute_shared_secret(peer_public: int, private: int, p: int) -> int:
    return pow(peer_public, private, p)

def derive_aes_key_from_ks(ks_int: int) -> bytes:
    # big-endian bytes of ks
    ks_bytes = ks_int.to_bytes((ks_int.bit_length()+7)//8 or 1, byteorder='big')
    h = sha256(ks_bytes).digest()
    return h[:16]

def gen_private_int(bitlen: int = 256) -> int:
    return secrets.randbits(bitlen)
