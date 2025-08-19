
"""
brute_force.py — Naïve brute-force password "cracker" for demo/education.
Attempts to recover a password by hashing candidate strings and comparing to a target.

⚠️ Educational use only. Do not use on systems you don't own or have explicit permission for.
"""

import time
import itertools
import string
from typing import Optional
from hashing import sha256_hash, pbkdf2_hash, HashRecord

def brute_force(record: HashRecord,
                min_len: int = 1,
                max_len: int = 5,
                charset: str = string.ascii_lowercase) -> Optional[str]:
    """
    Try all combinations in 'charset' from length min_len..max_len.
    Supports 'sha256' (fast) and 'pbkdf2' (slow) records.
    Returns the found password or None.
    """
    start = time.time()

    for length in range(min_len, max_len + 1):
        for combo in itertools.product(charset, repeat=length):
            candidate = ''.join(combo)
            if record.algo == "sha256":
                h = sha256_hash(candidate, record.salt)
            elif record.algo == "pbkdf2":
                # WARNING: This will be slow; PBKDF2 is intentionally costly.
                h = pbkdf2_hash(candidate, record.salt, record.iterations, record.dklen)
            else:
                raise ValueError("Unsupported algo in record.")
            if h == record.hash_hex:
                elapsed = time.time() - start
                return candidate
    return None
