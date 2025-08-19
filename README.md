
# Password Cracking and Hashing Algorithms (Project 7)

A compact, educational Python project that demonstrates:
- **Password hashing** with **SHA-256 + random salt** (and PBKDF2 option)
- A **naïve brute-force cracker** for short passwords (4–5 chars)

> ⚠️ **For learning only.** Do not use on any system without explicit permission.

---

## 🔧 Tech
- Python 3.8+
- Standard library only (`hashlib`, `os`, `itertools`, etc.)

## ▶️ Quick Start

```bash
# Optional: create a virtual environment
python -m venv .venv
# Windows
.venv\Scripts\activate
# macOS/Linux
source .venv/bin/activate

# Clone / unzip, then:
python demo.py
```

---

## 📚 What You'll See

### 1) Hash & Verify
- Enter a password
- Choose algorithm (`sha256` or `pbkdf2`)
- See: **salt (hex)** and **hash (hex)**
- Re-enter to verify

### 2) Brute-force Demo (sha256 + salt)
- The script chooses a random 4-letter lowercase password
- You see the **salt** and **hash**
- Brute-force tries 1–4 characters and recovers it
- Time taken is printed

### 3) Custom Brute-force
- Paste your own **salt (hex)** and **hash (hex)** (sha256 mode)
- Choose charset and length range
- Attempts recovery (can take long with big search space)

---

## 📎 Why Hash + Salt?
- Hashing is **one-way**: you store the hash, not the password.
- **Salt** makes precomputed attacks (rainbow tables) ineffective.
- **PBKDF2** slows attackers further (key stretching).

---

## ⚠️ Ethical Use
This code is for **education**. Only test on passwords/data you own or have permission to test. Misuse may be illegal.

---
