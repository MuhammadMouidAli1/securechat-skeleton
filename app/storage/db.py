# app/storage/db.py
import os
import argparse
import mysql.connector
from pathlib import Path
from dotenv import load_dotenv
from hashlib import sha256
import secrets

load_dotenv(dotenv_path=Path(__file__).resolve().parent.parent.parent / ".env")

DB_CONFIG = {
    "host": os.getenv("DB_HOST", "127.0.0.1"),
    "user": os.getenv("DB_USER", "scuser"),
    "password": os.getenv("DB_PASSWORD", "scpass"),
    "database": os.getenv("DB_NAME", "securechat"),
    "port": int(os.getenv("DB_PORT", "3306"))
}

def init_db():
    conn = mysql.connector.connect(host=DB_CONFIG["host"], user=os.getenv("DB_ROOT_USER","root"),
                                   password=os.getenv("DB_ROOT_PASS","rootpass"))
    cur = conn.cursor()
    cur.execute(f"CREATE DATABASE IF NOT EXISTS {DB_CONFIG['database']}")
    cur.execute(f"USE {DB_CONFIG['database']}")
    cur.execute("""CREATE TABLE IF NOT EXISTS users(
        email VARCHAR(256) PRIMARY KEY,
        username VARCHAR(128) UNIQUE,
        salt VARBINARY(16),
        pwd_hash CHAR(64)
    )""")
    conn.commit()
    cur.close()
    conn.close()
    print("DB initialized and table created.")

def add_user(email, username, password):
    salt = secrets.token_bytes(16)
    pwd_hash = sha256(salt + password.encode()).hexdigest()
    conn = mysql.connector.connect(**DB_CONFIG)
    cur = conn.cursor()
    cur.execute("INSERT INTO users (email, username, salt, pwd_hash) VALUES (%s,%s,%s,%s)",
                (email, username, salt, pwd_hash))
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
