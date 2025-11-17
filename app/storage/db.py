# app/storage/db.py
"""
DB helper for securechat assignment.
Provides:
 - --init : create database and users table (connects as root using DB_ROOT_USER/DB_ROOT_PASS on configured DB_PORT)
 - --add : add a sample user (email username password) using salted SHA256
"""
import os
import argparse
import mysql.connector
from pathlib import Path
from dotenv import load_dotenv
from hashlib import sha256
import secrets

ROOT = Path(__file__).resolve().parents[2]
load_dotenv(ROOT / ".env")

DB_HOST = os.getenv("DB_HOST", "127.0.0.1")
DB_PORT = int(os.getenv("DB_PORT", "3307"))
DB_USER = os.getenv("DB_USER", "scuser")
DB_PASS = os.getenv("DB_PASSWORD", "scpass")
DB_NAME = os.getenv("DB_NAME", "securechat")

DB_ROOT_USER = os.getenv("DB_ROOT_USER", "root")
DB_ROOT_PASS = os.getenv("DB_ROOT_PASS", "rootpass")

def init_db():
    # Connect as root (explicit port) to create DB and table
    conn = mysql.connector.connect(
        host=DB_HOST, port=DB_PORT,
        user=DB_ROOT_USER, password=DB_ROOT_PASS
    )
    cur = conn.cursor()
    cur.execute(f"CREATE DATABASE IF NOT EXISTS `{DB_NAME}`")
    cur.execute(f"USE `{DB_NAME}`")
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        email VARCHAR(256) PRIMARY KEY,
        username VARCHAR(128) UNIQUE,
        salt VARBINARY(16),
        pwd_hash CHAR(64)
    )
    """)
    conn.commit()
    cur.close()
    conn.close()
    print("DB initialized and table created.")

def add_user(email, username, password):
    salt = secrets.token_bytes(16)
    pwd_hash = sha256(salt + password.encode()).hexdigest()
    conn = mysql.connector.connect(host=DB_HOST, port=DB_PORT, user=DB_USER, password=DB_PASS, database=DB_NAME)
    cur = conn.cursor()
    cur.execute("INSERT INTO users (email, username, salt, pwd_hash) VALUES (%s,%s,%s,%s)", (email, username, salt, pwd_hash))
    conn.commit()
    cur.close()
    conn.close()
    print("Added user:", email)

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--init", action="store_true")
    p.add_argument("--add", nargs=3, metavar=('email','username','password'))
    args = p.parse_args()
    if args.init:
        init_db()
    if args.add:
        add_user(*args.add)
