
"""
hashing.py — Simple password hashing utilities.
Implements:
  - SHA-256 with random salt (fast; for demo)
  - PBKDF2-HMAC-SHA256 (slow; recommended in practice)

This module uses ONLY Python's standard library.
"""

import os
import hashlib
from dataclasses import dataclass

DEFAULT_SALT_LEN = 16
DEFAULT_PBKDF2_ITERS = 200_000
DEFAULT_PBKDF2_DKLEN = 32  # 256-bit

@dataclass
class HashRecord:
    algo: str        # "sha256" or "pbkdf2"
    salt: bytes
    hash_hex: str
    iterations: int = DEFAULT_PBKDF2_ITERS
    dklen: int = DEFAULT_PBKDF2_DKLEN

def generate_salt(n: int = DEFAULT_SALT_LEN) -> bytes:
    return os.urandom(n)

def sha256_hash(password: str, salt: bytes) -> str:
    """Fast SHA-256(salt || password) hex digest. For demo only."""
    return hashlib.sha256(salt + password.encode('utf-8')).hexdigest()

def pbkdf2_hash(password: str, salt: bytes,
                iterations: int = DEFAULT_PBKDF2_ITERS,
                dklen: int = DEFAULT_PBKDF2_DKLEN) -> str:
    """Slower, stronger key-derivation (recommended)."""
    return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations, dklen).hex()

def hash_password(password: str, algo: str = "sha256") -> HashRecord:
    """
    Hash a password with a random salt.
    algo: "sha256" (demo) or "pbkdf2" (recommended)
    """
    salt = generate_salt()
    if algo == "pbkdf2":
        h = pbkdf2_hash(password, salt)
        return HashRecord(algo="pbkdf2", salt=salt, hash_hex=h)
    elif algo == "sha256":
        h = sha256_hash(password, salt)
        return HashRecord(algo="sha256", salt=salt, hash_hex=h)
    else:
        raise ValueError("Unsupported algo. Use 'sha256' or 'pbkdf2'.")

def verify_password(password: str, record: HashRecord) -> bool:
    if record.algo == "pbkdf2":
        return pbkdf2_hash(password, record.salt, record.iterations, record.dklen) == record.hash_hex
    elif record.algo == "sha256":
        return sha256_hash(password, record.salt) == record.hash_hex
    else:
        raise ValueError("Unsupported algo in record.")
