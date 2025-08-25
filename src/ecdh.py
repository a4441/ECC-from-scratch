from __future__ import annotations
import hashlib
from .curve import Point

def kdf_sha256(x: bytes) -> bytes:
    """Simple one-step KDF using SHA-256 (for demo purposes)."""
    return hashlib.sha256(x).digest()

def ecdh_shared_secret(priv: int, peer_pub: Point) -> bytes:
    if not (1 <= priv < peer_pub.curve.n):
        raise ValueError("invalid private key scalar")
    S = priv * peer_pub  # shared point
    if S.is_infinity():
        raise ValueError("invalid shared point (infinity)")
    # return KDF(x-coordinate)
    x_bytes = S.x.to_bytes((S.x.bit_length() + 7) // 8, 'big')
    return kdf_sha256(x_bytes)
