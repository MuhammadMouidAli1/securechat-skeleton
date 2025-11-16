# app/crypto/aes.py
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import os
import base64

BLOCK_SIZE = 128  # bits

def pad(data: bytes) -> bytes:
    padder = padding.PKCS7(BLOCK_SIZE).padder()
    return padder.update(data) + padder.finalize()

def unpad(data: bytes) -> bytes:
    unpadder = padding.PKCS7(BLOCK_SIZE).unpadder()
    return unpadder.update(data) + unpadder.finalize()

def encrypt_aes_ecb(key: bytes, plaintext: bytes) -> bytes:
    if len(key) != 16:
        raise ValueError("AES-128 key must be 16 bytes")
    plaintext_p = pad(plaintext)
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    encryptor = cipher.encryptor()
    ct = encryptor.update(plaintext_p) + encryptor.finalize()
    return ct

def decrypt_aes_ecb(key: bytes, ciphertext: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    decryptor = cipher.decryptor()
    pt_p = decryptor.update(ciphertext) + decryptor.finalize()
    return unpad(pt_p)

def b64enc(b: bytes) -> str:
    return base64.b64encode(b).decode()

def b64dec(s: str) -> bytes:
    return base64.b64decode(s)
