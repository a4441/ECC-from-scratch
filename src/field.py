from __future__ import annotations
from dataclasses import dataclass

@dataclass(frozen=True)
class PrimeField:
    """Represents a prime field GF(p)."""
    p: int

    def normalize(self, x: int) -> int:
        return x % self.p

    def add(self, a: int, b: int) -> int:
        return (a + b) % self.p

    def sub(self, a: int, b: int) -> int:
        return (a - b) % self.p

    def mul(self, a: int, b: int) -> int:
        return (a * b) % self.p

    def neg(self, a: int) -> int:
        return (-a) % self.p

    def inv(self, a: int) -> int:
        if a % self.p == 0:
            raise ZeroDivisionError("inverse of zero does not exist")
        # Using Fermat's little theorem since p is prime
        return pow(a, self.p - 2, self.p)

    def div(self, a: int, b: int) -> int:
        return self.mul(a, self.inv(b))

    def pow(self, a: int, e: int) -> int:
        return pow(a, e, self.p)
