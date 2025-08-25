from __future__ import annotations
from dataclasses import dataclass
from typing import Tuple
import hashlib, hmac, secrets

from .curve import Curve, Point, G

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def bits2int(b: bytes, qlen: int, n: int) -> int:
    i = int.from_bytes(b, 'big')
    blen = len(b) * 8
    if blen > qlen:
        i >>= (blen - qlen)
    return i % n

def int2octets(x: int, rolen: int) -> bytes:
    return x.to_bytes(rolen, 'big')

def bits2octets(b: bytes, n: int) -> bytes:
    z1 = int.from_bytes(b, 'big')
    z2 = z1 % n
    qlen = n.bit_length()
    rolen = (qlen + 7) // 8
    return int2octets(z2, rolen)

def rfc6979_generate_k(priv: int, h1: bytes, n: int) -> int:
    """Deterministic nonces per RFC 6979 (using SHA-256)."""
    qlen = n.bit_length()
    rolen = (qlen + 7) // 8
    bx = int2octets(priv, rolen) + bits2octets(h1, n)
    V = b"\x01" * 32
    K = b"\x00" * 32
    K = hmac.new(K, V + b"\x00" + bx, hashlib.sha256).digest()
    V = hmac.new(K, V, hashlib.sha256).digest()
    K = hmac.new(K, V + b"\x01" + bx, hashlib.sha256).digest()
    V = hmac.new(K, V, hashlib.sha256).digest()
    while True:
        T = b""
        while len(T) < rolen:
            V = hmac.new(K, V, hashlib.sha256).digest()
            T += V
        k = bits2int(T, qlen, n)
        if 1 <= k < n:
            return k
        K = hmac.new(K, V + b"\x00", hashlib.sha256).digest()
        V = hmac.new(K, V, hashlib.sha256).digest()

@dataclass
class KeyPair:
    curve: Curve
    priv: int
    pub: Point

    @staticmethod
    def generate(curve: Curve) -> 'KeyPair':
        while True:
            d = secrets.randbelow(curve.n)
            if 1 <= d < curve.n:
                break
        Q = d * G(curve)
        return KeyPair(curve, d, Q)

def sign(priv: int, msg: bytes, curve: Curve) -> Tuple[int, int]:
    """ECDSA sign with RFC 6979 deterministic k and low-S normalization."""
    n = curve.n
    h1 = sha256(msg)
    k = rfc6979_generate_k(priv, h1, n)
    R = k * G(curve)
    r = R.x % n
    if r == 0:
        return sign(priv, msg, curve)  # extremely unlikely
    kinv = pow(k, -1, n)
    e = int.from_bytes(h1, 'big') % n
    s = (kinv * (e + r * priv)) % n
    if s == 0:
        return sign(priv, msg, curve)
    # low-S normalization
    if s > n // 2:
        s = n - s
    return r, s

def verify(pub: Point, msg: bytes, sig: Tuple[int, int]) -> bool:
    r, s = sig
    n = pub.curve.n
    if not (1 <= r < n and 1 <= s < n):
        return False
    e = int.from_bytes(sha256(msg), 'big') % n
    w = pow(s, -1, n)
    u1 = (e * w) % n
    u2 = (r * w) % n
    P = u1 * G(pub.curve) + u2 * pub
    if P.is_infinity():
        return False
    return (P.x % n) == r
