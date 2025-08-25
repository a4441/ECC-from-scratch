from __future__ import annotations
from .curve import SECP256R1, SECP256K1, G
from .ecdsa import KeyPair, sign, verify
from .ecdh import ecdh_shared_secret

def main():
    print("== ECC from scratch demo ==")

    # Key generation (P-256)
    alice = KeyPair.generate(SECP256R1)
    print(f"Alice priv: 0x{alice.priv:064x}")
    print(f"Alice pub:  ({hex(alice.pub.x)},\n             {hex(alice.pub.y)})")

    # Sign/verify
    msg = b"hello elliptic curves"
    sig = sign(alice.priv, msg, alice.curve)
    print("Signature (r,s) =", tuple(hex(x) for x in sig))
    ok = verify(alice.pub, msg, sig)
    print("Verify:", ok)

    # ECDH (secp256k1)
    bob = KeyPair.generate(SECP256K1)
    carol = KeyPair.generate(SECP256K1)
    shared1 = ecdh_shared_secret(bob.priv, carol.pub)
    shared2 = ecdh_shared_secret(carol.priv, bob.pub)
    print("ECDH matches:", shared1 == shared2)
    print("Shared secret (SHA-256(x)):", shared1.hex())

if __name__ == "__main__":
    main()
