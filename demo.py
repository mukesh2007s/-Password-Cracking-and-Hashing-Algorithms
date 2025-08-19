
"""
demo.py — Run simple demos:
  1) Hash & verify a user password
  2) Brute-force a short, randomly chosen password (sha256+salt)
  3) Custom brute-force against your own salted hash

Run:
  python demo.py
"""

import time
import random
import string
from dataclasses import asdict
from hashing import hash_password, verify_password, HashRecord, sha256_hash
from brute_force import brute_force

def print_record(record: HashRecord):
    print("Algorithm :", record.algo)
    print("Salt (hex):", record.salt.hex())
    print("Hash (hex):", record.hash_hex)
    if record.algo == "pbkdf2":
        print("PBKDF2 iterations:", record.iterations)
        print("PBKDF2 dklen    :", record.dklen)

def menu():
    print("=== Password Hashing & Brute-Force Demo ===")
    print("1) Hash & verify a user password")
    print("2) Brute-force a short random password (sha256+salt)")
    print("3) Custom brute-force against your own salted hash")
    print("0) Exit")
    choice = input("Choose: ").strip()
    return choice

def option1():
    print("\n[1] Hash & verify")
    password = input("Enter a password: ")
    algo = input("Choose algo ('sha256' or 'pbkdf2') [sha256]: ").strip() or "sha256"
    record = hash_password(password, algo=algo)
    print("\nStored record:")
    print_record(record)
    print("\nNow verifying...")
    check = input("Re-enter password: ")
    ok = verify_password(check, record)
    print("Match?", ok)

def option2():
    print("\n[2] Brute-force a short random password (sha256+salt)")
    # pick a 4-letter lowercase password
    charset = string.ascii_lowercase
    secret = ''.join(random.choice(charset) for _ in range(4))
    record = hash_password(secret, algo="sha256")
    print("Target hash (hex):", record.hash_hex)
    print("Salt (hex)       :", record.salt.hex())
    print("Searching... (this may take a few seconds)")
    start = time.time()
    found = brute_force(record, min_len=1, max_len=4, charset=charset)
    elapsed = time.time() - start
    print("Found password   :", found)
    print(f"Time taken       : {elapsed:.2f} seconds")

def option3():
    print("\n[3] Custom brute-force against your own salted hash (sha256 only)")
    hhex = input("Enter target hash (hex): ").strip()
    salt_hex = input("Enter salt (hex): ").strip()
    try:
        salt = bytes.fromhex(salt_hex)
    except ValueError:
        print("Invalid salt hex.")
        return
    # Only sha256 for practical demo speed
    record = HashRecord(algo="sha256", salt=salt, hash_hex=hhex)
    charset = input("Charset [lowercase]: ").strip()
    if not charset:
        import string as _s
        charset = _s.ascii_lowercase
    try:
        min_len = int(input("Min length [1]: ") or "1")
        max_len = int(input("Max length [5]: ") or "5")
    except ValueError:
        print("Invalid length.")
        return
    print("Brute-forcing...")
    start = time.time()
    found = brute_force(record, min_len=min_len, max_len=max_len, charset=charset)
    elapsed = time.time() - start
    print("Found password:", found)
    print(f"Time taken    : {elapsed:.2f} seconds")

if __name__ == "__main__":
    while True:
        c = menu()
        if c == "1":
            option1()
        elif c == "2":
            option2()
        elif c == "3":
            option3()
        elif c == "0":
            print("Bye!")
            break
        else:
            print("Invalid choice. Try again.")
        print("\n" + "-"*50 + "\n")
