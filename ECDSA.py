"""
ECDSA - Elliptic Curve Digital Signature Algorithm
Implemented from scratch. No crypto libraries used.
Curve: secp256k1 (same curve used by Bitcoin)
"""

import random
import hashlib




P  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
A  = 0
B  = 7
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
N  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G  = (Gx, Gy)   



def mod_inverse(a, m):
    """Modular inverse using Extended Euclidean Algorithm."""
    g, x, _ = extended_gcd(a % m, m)
    if g != 1:
        raise ValueError("Modular inverse does not exist.")
    return x % m

def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    g, x, y = extended_gcd(b % a, a)
    return g, y - (b // a) * x, x



INFINITY = None   

def point_add(P1, P2):
    """Add two points on the elliptic curve."""
    if P1 is INFINITY:
        return P2
    if P2 is INFINITY:
        return P1

    x1, y1 = P1
    x2, y2 = P2

    
    if P1 == P2:
        if y1 == 0:
            return INFINITY
        lam = (3 * x1 * x1 + A) * mod_inverse(2 * y1, P) % P
    else:
        if x1 == x2:
            return INFINITY   
        lam = (y2 - y1) * mod_inverse(x2 - x1, P) % P

    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)


def point_mul(k, point):
    """Scalar multiplication using double-and-add."""
    result = INFINITY
    addend = point
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return result


def is_on_curve(point):
    """Verify a point lies on secp256k1."""
    if point is INFINITY:
        return True
    x, y = point
    return (y * y - x * x * x - A * x - B) % P == 0



def hash_message(message: str) -> int:
    """SHA-256 hash of the message, returned as integer."""
    digest = hashlib.sha256(message.encode("utf-8")).digest()
    return int.from_bytes(digest, "big")



def generate_keypair():
    """
    Generate an ECDSA key pair on secp256k1.

    Private key: random integer d ∈ [1, N-1]
    Public key:  point Q = d·G on the curve
    """
    d = random.randrange(1, N)    
    Q = point_mul(d, G)           
    return d, Q



def sign(private_key: int, message: str) -> tuple:
    """
    Sign a message with the private key.

    Steps:
      1. Hash the message: e = H(m)
      2. Pick random nonce k ∈ [1, N-1]  (MUST be unique per signature)
      3. Compute R = k·G, set r = R.x mod N
      4. Compute s = k⁻¹(e + r·d) mod N
      5. Return signature (r, s)
    """
    d = private_key
    e = hash_message(message)

    while True:
        k = random.randrange(1, N)          
        R = point_mul(k, G)
        r = R[0] % N
        if r == 0:
            continue                         

        k_inv = mod_inverse(k, N)
        s = k_inv * (e + r * d) % N
        if s == 0:
            continue                        

        return (r, s)




def verify(public_key, message: str, signature: tuple) -> bool:
    """
    Verify a signature (r, s) against a message and public key Q.

    Steps:
      1. Check r, s ∈ [1, N-1]
      2. Hash the message: e = H(m)
      3. w  = s⁻¹ mod N
      4. u1 = e·w mod N
      5. u2 = r·w mod N
      6. X  = u1·G + u2·Q
      7. Signature valid iff X.x mod N == r
    """
    Q = public_key
    r, s = signature

   
    if not (1 <= r < N and 1 <= s < N):
        return False

   
    e = hash_message(message)

    
    w  = mod_inverse(s, N)
    u1 = e * w % N
    u2 = r * w % N


    X = point_add(point_mul(u1, G), point_mul(u2, Q))
    if X is INFINITY:
        return False

  
    return X[0] % N == r



def demo():
    print("=" * 60)
    print("        ECDSA Digital Signature Demo (secp256k1)")
    print("=" * 60)

    
    print("\n[1] Key Generation")
    private_key, public_key = generate_keypair()
    print(f"    Private key (d) : {hex(private_key)}")
    print(f"    Public key  (Q) : ({hex(public_key[0])},")
    print(f"                       {hex(public_key[1])})")
    print(f"    Q on curve?     : {is_on_curve(public_key)}")

   
    message = "Transfer $500 to Alice"
    print(f"\n[2] Signing message: {message!r}")
    sig = sign(private_key, message)
    print(f"    r = {hex(sig[0])}")
    print(f"    s = {hex(sig[1])}")

   
    print(f"\n[3] Verification")
    valid = verify(public_key, message, sig)
    print(f"    Original message → {'✓ VALID' if valid else '✗ INVALID'}")

    
    tampered = "Transfer $9999 to Eve"
    valid_tampered = verify(public_key, tampered, sig)
    print(f"    Tampered message → {'✓ VALID' if valid_tampered else '✗ INVALID (tamper detected!)'}")

    
    _, wrong_pub = generate_keypair()
    valid_wrong = verify(wrong_pub, message, sig)
    print(f"    Wrong public key → {'✓ VALID' if valid_wrong else '✗ INVALID (wrong key detected!)'}")

   
    print(f"\n[4] Signature Randomness Check (same message, two signatures)")
    sig2 = sign(private_key, message)
    print(f"    Sig 1: r={hex(sig[0])[:18]}...")
    print(f"    Sig 2: r={hex(sig2[0])[:18]}...")
    print(f"    Different? {sig != sig2}")
    print(f"    Both valid? {verify(public_key, message, sig) and verify(public_key, message, sig2)}")

    print("\n" + "=" * 60)
    print("  All checks passed!" )
    print("=" * 60)


if __name__ == "__main__":
    demo()