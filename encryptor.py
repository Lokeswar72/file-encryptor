#!/usr/bin/env python3
"""
encryptor.py

AES-256-GCM file encryptor with a wrapped master key protected by a password (scrypt KEK).
Interactive password prompts used (no passphrase on command line).
"""

import argparse
import sys
from pathlib import Path
import secrets
import getpass

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# -------------------- Configuration --------------------
KEY_DIR = Path("keys")
KEY_DIR.mkdir(exist_ok=True)
MASTER_KEY_ENC_PATH = KEY_DIR / "master_key.bin.enc"

# -------------------- KDF / KEK derivation --------------------
def derive_kek(password: bytes, salt: bytes, n: int = 2**14, r: int = 8, p: int = 1, length: int = 32) -> bytes:
    """
    Derive a key-encryption-key (KEK) using scrypt from a password and salt.
    """
    kdf = Scrypt(salt=salt, length=length, n=n, r=r, p=p)
    return kdf.derive(password)

# -------------------- Master key handling --------------------
def generate_master_key() -> bytes:
    return secrets.token_bytes(32)  # 256-bit key

def wrap_master_key(master_key: bytes, password: str) -> bytes:
    """
    Wrap (encrypt) the master key using a password-derived KEK.
    Format: 16-byte salt || 12-byte nonce || ciphertext
    """
    salt = secrets.token_bytes(16)
    kek = derive_kek(password.encode("utf-8"), salt)
    aesgcm = AESGCM(kek)
    nonce = secrets.token_bytes(12)
    ct = aesgcm.encrypt(nonce, master_key, None)
    return salt + nonce + ct

def unwrap_master_key(wrapped: bytes, password: str) -> bytes:
    salt = wrapped[:16]
    nonce = wrapped[16:28]
    ct = wrapped[28:]
    kek = derive_kek(password.encode("utf-8"), salt)
    aesgcm = AESGCM(kek)
    return aesgcm.decrypt(nonce, ct, None)

def save_wrapped_master_key(path: Path, wrapped_bytes: bytes) -> None:
    path.write_bytes(wrapped_bytes)
    try:
        # restrict permissions on Unix-like systems (harmless on Windows)
        path.chmod(0o600)
    except Exception:
        pass

def load_wrapped_master_key(path: Path) -> bytes:
    return path.read_bytes()

# -------------------- File encrypt/decrypt with master --------------------
def encrypt_file_with_master(master_key: bytes, in_path: Path, out_path: Path) -> None:
    aesgcm = AESGCM(master_key)
    nonce = secrets.token_bytes(12)
    plaintext = in_path.read_bytes()
    ct = aesgcm.encrypt(nonce, plaintext, None)
    out_path.write_bytes(nonce + ct)

def decrypt_file_with_master(master_key: bytes, in_path: Path, out_path: Path) -> None:
    data = in_path.read_bytes()
    if len(data) < 13:
        raise ValueError("Input file too small or corrupted.")
    nonce = data[:12]
    ct = data[12:]
    aesgcm = AESGCM(master_key)
    pt = aesgcm.decrypt(nonce, ct, None)
    out_path.write_bytes(pt)

# -------------------- CLI commands --------------------
def cmd_generate(args):
    if MASTER_KEY_ENC_PATH.exists():
        print("Wrapped master key already exists at", MASTER_KEY_ENC_PATH)
        return
    # interactive password entry
    password = getpass.getpass("Enter password to protect the master key: ")
    if not password:
        print("Empty password is not allowed.")
        return
    password2 = getpass.getpass("Confirm password: ")
    if password != password2:
        print("Passwords do not match. Aborting.")
        return
    mk = generate_master_key()
    wrapped = wrap_master_key(mk, password)
    save_wrapped_master_key(MASTER_KEY_ENC_PATH, wrapped)
    print("Generated and wrapped master key ->", MASTER_KEY_ENC_PATH)

def cmd_change_password(args):
    """
    Change the password that protects the wrapped master key.
    This unwraps the master key using the current password, then re-wraps it with the new password.
    """
    if not MASTER_KEY_ENC_PATH.exists():
        print("No wrapped master key found. Run `generate-master-key` first.")
        return

    # Get current password and try to unwrap
    old_password = getpass.getpass("Enter current password to unwrap the master key: ")
    wrapped = load_wrapped_master_key(MASTER_KEY_ENC_PATH)
    try:
        master_key = unwrap_master_key(wrapped, old_password)
    except Exception as e:
        print("Failed to unwrap master key with the provided current password:", str(e))
        return

    # Get new password (confirm)
    new_password = getpass.getpass("Enter NEW password to protect the master key: ")
    if not new_password:
        print("Empty password is not allowed.")
        return
    new_password2 = getpass.getpass("Confirm NEW password: ")
    if new_password != new_password2:
        print("New passwords do not match. Aborting.")
        return

    # Re-wrap master key and write atomically
    new_wrapped = wrap_master_key(master_key, new_password)
    tmp_path = MASTER_KEY_ENC_PATH.with_suffix(".enc.tmp")
    tmp_path.write_bytes(new_wrapped)
    try:
        tmp_path.chmod(0o600)
    except Exception:
        pass
    tmp_path.replace(MASTER_KEY_ENC_PATH)  # atomic on most OSes
    print("Master key re-wrapped with new password ->", MASTER_KEY_ENC_PATH)


def cmd_encrypt(args):
    if not MASTER_KEY_ENC_PATH.exists():
        print("No wrapped master key found. Run `generate-master-key` first.")
        return
    password = getpass.getpass("Enter password to unwrap the master key: ")
    wrapped = load_wrapped_master_key(MASTER_KEY_ENC_PATH)
    try:
        master_key = unwrap_master_key(wrapped, password)
    except Exception as e:
        print("Failed to unwrap master key:", str(e))
        return
    in_path = Path(args.input)
    if not in_path.exists():
        print("Input file does not exist:", in_path)
        return
    out_path = Path(args.output) if args.output else in_path.with_suffix(in_path.suffix + ".enc")
    encrypt_file_with_master(master_key, in_path, out_path)
    print("Encrypted", in_path, "->", out_path)

def cmd_decrypt(args):
    if not MASTER_KEY_ENC_PATH.exists():
        print("No wrapped master key found. Run `generate-master-key` first.")
        return
    password = getpass.getpass("Enter password to unwrap the master key: ")
    wrapped = load_wrapped_master_key(MASTER_KEY_ENC_PATH)
    try:
        master_key = unwrap_master_key(wrapped, password)
    except Exception as e:
        print("Failed to unwrap master key:", str(e))
        return
    in_path = Path(args.input)
    if not in_path.exists():
        print("Input file does not exist:", in_path)
        return
    # default output: remove '.enc' if present, else add '.dec'
    if args.output:
        out_path = Path(args.output)
    else:
        if in_path.suffix == ".enc":
            out_path = in_path.with_suffix("")  # remove .enc
        else:
            out_path = in_path.with_suffix(in_path.suffix + ".dec")
    try:
        decrypt_file_with_master(master_key, in_path, out_path)
    except Exception as e:
        print("Decryption failed:", str(e))
        return
    print("Decrypted", in_path, "->", out_path)

def build_parser():
    p = argparse.ArgumentParser(description="File encryption tool using AES-GCM + wrapped master key")
    sp = p.add_subparsers(dest="cmd")

    g = sp.add_parser("generate-master-key", help="Create and wrap a new master key (password-protected)")
    g.set_defaults(func=cmd_generate)

    e = sp.add_parser("encrypt", help="Encrypt a file")
    e.add_argument("input", help="Input file to encrypt")
    e.add_argument("output", nargs="?", help="Output encrypted file (optional)")
    e.set_defaults(func=cmd_encrypt)

    d = sp.add_parser("decrypt", help="Decrypt a file")
    d.add_argument("input", help="Encrypted input file")
    d.add_argument("output", nargs="?", help="Output decrypted file (optional)")
    d.set_defaults(func=cmd_decrypt)

    c = sp.add_parser("change-password", help="Change password used to protect the wrapped master key")
    c.set_defaults(func=cmd_change_password)

    return p

def main(argv=None):
    p = build_parser()
    args = p.parse_args(argv)
    if not hasattr(args, "func"):
        p.print_help()
        sys.exit(1)
    args.func(args)

if __name__ == "__main__":
    main()
