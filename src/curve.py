from __future__ import annotations
from dataclasses import dataclass
from typing import Optional, Tuple

from .field import PrimeField

@dataclass(frozen=True)
class Curve:
    """Short Weierstrass curve y^2 = x^3 + a*x + b (mod p)."""
    name: str
    p: int
    a: int
    b: int
    Gx: int
    Gy: int
    n: int    # order of base point
    h: int = 1

    @property
    def F(self) -> PrimeField:
        return PrimeField(self.p)

@dataclass
class Point:
    curve: Curve
    x: Optional[int]
    y: Optional[int]

    def is_infinity(self) -> bool:
        return self.x is None and self.y is None

    @staticmethod
    def infinity(curve: Curve) -> 'Point':
        return Point(curve, None, None)

    def __post_init__(self):
        # Validate point lies on curve (skip for infinity)
        if not self.is_infinity():
            F = self.curve.F
            x, y = self.x % F.p, self.y % F.p
            if F.pow(y, 2) != (F.pow(x, 3) + F.mul(self.curve.a, x) + self.curve.b) % F.p:
                raise ValueError("Point is not on the curve")
            self.x, self.y = x, y

    def __neg__(self) -> 'Point':
        if self.is_infinity():
            return self
        F = self.curve.F
        return Point(self.curve, self.x, F.neg(self.y))

    def __add__(self, other: 'Point') -> 'Point':
        if self.curve is not other.curve:
            raise TypeError("Points on different curves")
        F = self.curve.F

        # Handle identity
        if self.is_infinity():
            return other
        if other.is_infinity():
            return self

        x1, y1, x2, y2 = self.x, self.y, other.x, other.y

        if x1 == x2 and (y1 != y2 or y1 == 0):
            return Point.infinity(self.curve)  # P + (-P) = O ; or tangent vertical

        if x1 == x2 and y1 == y2:
            # Point doubling
            s = F.div(F.add(F.mul(3, F.pow(x1, 2)), self.curve.a), F.mul(2, y1))
        else:
            # Point addition
            s = F.div(F.sub(y2, y1), F.sub(x2, x1))

        x3 = F.sub(F.sub(F.pow(s, 2), x1), x2)
        y3 = F.sub(F.mul(s, F.sub(x1, x3)), y1)
        return Point(self.curve, x3, y3)

    def double(self) -> 'Point':
        return self + self

    def __rmul__(self, k: int) -> 'Point':
        return scalar_mult(k, self)

def scalar_mult(k: int, P: Point) -> Point:
    """Double-and-add scalar multiplication (variable-time; not constant-time)."""
    if k % P.curve.n == 0 or P.is_infinity():
        return Point.infinity(P.curve)
    if k < 0:
        return scalar_mult(-k, -P)
    Q = Point.infinity(P.curve)
    base = P
    while k:
        if k & 1:
            Q = Q + base
        base = base.double()
        k >>= 1
    return Q

# Optional: Windowed NAF for a speedup (still variable-time)
def wnaf_scalar_mult(k: int, P: Point, w: int = 5) -> Point:
    if k % P.curve.n == 0 or P.is_infinity():
        return Point.infinity(P.curve)
    if k < 0:
        return wnaf_scalar_mult(-k, -P, w)

    # precompute odd multiples P,3P,5P,...
    precomp = [P]
    twoP = P.double()
    for _ in range(1, 1 << (w-2)):
        precomp.append(precomp[-1] + twoP)

    # compute wNAF digits
    naf = []
    while k > 0:
        if k & 1:
            zi = k % (1 << w)
            if zi > (1 << (w-1)):
                zi -= 1 << w
            k -= zi
        else:
            zi = 0
        naf.append(zi)
        k >>= 1
    # accumulate
    Q = Point.infinity(P.curve)
    for zi in reversed(naf):
        Q = Q.double()
        if zi != 0:
            idx = (abs(zi) - 1) // 2
            addend = precomp[idx]
            Q = Q + (addend if zi > 0 else -addend)
    return Q

# ---- Curves ----

# secp256r1 (aka NIST P-256)
SECP256R1 = Curve(
    name="secp256r1",
    p=0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff,
    a=0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc,  # -3 mod p
    b=0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b,
    Gx=0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
    Gy=0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5,
    n=0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551,
    h=1,
)

# secp256k1
SECP256K1 = Curve(
    name="secp256k1",
    p=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F,
    a=0,
    b=7,
    Gx=0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    Gy=0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
    n=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
    h=1,
)

def G(curve: Curve) -> Point:
    return Point(curve, curve.Gx, curve.Gy)
