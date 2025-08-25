from __future__ import annotations
import hashlib
from src.curve import SECP256R1, SECP256K1, G, Point
from src.curve import scalar_mult
from src.ecdsa import KeyPair, sign, verify
from src.ecdh import ecdh_shared_secret

def test_group_identity():
    O = Point.infinity(SECP256R1)
    P = G(SECP256R1)
    assert (P + O).x == P.x and (P + O).y == P.y
    assert (O + P).x == P.x and (O + P).y == P.y

def test_group_inverse():
    P = G(SECP256R1)
    O = Point.infinity(SECP256R1)
    assert P + (-P) == O

def test_scalar_mult_basic():
    P = G(SECP256R1)
    n = SECP256R1.n
    assert scalar_mult(n, P).is_infinity()  # order * G = O
    assert (2 * P) == P + P

def test_ecdsa_sign_verify():
    kp = KeyPair.generate(SECP256R1)
    msg = b"unit test message"
    sig = sign(kp.priv, msg, kp.curve)
    assert verify(kp.pub, msg, sig)

def test_ecdh():
    a = KeyPair.generate(SECP256K1)
    b = KeyPair.generate(SECP256K1)
    s1 = ecdh_shared_secret(a.priv, b.pub)
    s2 = ecdh_shared_secret(b.priv, a.pub)
    assert s1 == s2
