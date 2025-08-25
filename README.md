# ECC From Scratch (Pure Python)

An educational implementation of Elliptic Curve Cryptography to help you **explore and understand** the building blocks: finite fields, points on curves, scalar multiplication, ECDSA (deterministic RFC 6979), and ECDH.

> ⚠️ **Security disclaimer**: This is **for learning only**. No constant-time arithmetic. Do **not** use in production.

## Features
- Finite field arithmetic over prime fields `GF(p)`
- Elliptic curve group law (short Weierstrass form)
- Scalar multiplication (double-and-add, with w-NAF option for speed)
- Two built-in curves: **secp256r1 (NIST P-256)** and **secp256k1**
- ECDSA sign/verify (deterministic k via **RFC 6979**; low-S normalization)
- ECDH (Elliptic Curve Diffie–Hellman) key agreement
- Clean, type-annotated code with tests

## Quickstart

```bash
# (optional) create venv
python -m venv .venv && source .venv/bin/activate  # on Windows: .venv\Scripts\activate

# run example
python -m src.examples

# run tests
python -m pip install -U pytest
pytest
```

## Example

```python
from src.curve import SECP256R1, SECP256K1
from src.ecdsa import KeyPair, sign, verify
from src.ecdh import ecdh_shared_secret

# generate key on secp256r1
kp = KeyPair.generate(SECP256R1)
msg = b"hello elliptic curves"
sig = sign(kp.priv, msg, kp.curve)
assert verify(kp.pub, msg, sig)

# ECDH
alice = KeyPair.generate(SECP256K1)
bob   = KeyPair.generate(SECP256K1)
shared1 = ecdh_shared_secret(alice.priv, bob.pub)
shared2 = ecdh_shared_secret(bob.priv, alice.pub)
assert shared1 == shared2
print("ECDH OK, shared secret:", shared1.hex())
```

## Project Layout
```
src/
  field.py      # prime field arithmetic
  curve.py      # curve + point definitions & ops
  ecdsa.py      # ECDSA keygen/sign/verify (RFC6979)
  ecdh.py       # ECDH key agreement
  examples.py   # run me to see it work
tests/
  test_ecc.py
```

## Notes
- Deterministic `k` per RFC 6979 using SHA-256.
- Low-S normalization ensures unique signatures.
- Minimal input validation to keep things readable.

---

MIT © 2025
