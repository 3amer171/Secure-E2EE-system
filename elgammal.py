"""
ElGamal Public Key Encryption - Secure Version
Uses Python's secrets module instead of random
"""

import secrets



def mod_pow(base, exp, mod):
    """
    Fast modular exponentiation:
    computes (base^exp) mod mod efficiently
    """
    result = 1
    base %= mod

    while exp > 0:
        if exp & 1:
            result = (result * base) % mod

        base = (base * base) % mod
        exp >>= 1

    return result


def gcd(a, b):
    """Euclidean algorithm"""
    while b:
        a, b = b, a % b
    return a


def extended_gcd(a, b):
    """
    Extended Euclidean Algorithm

    Returns:
        gcd, x, y

    such that:
        ax + by = gcd(a,b)
    """
    if a == 0:
        return b, 0, 1

    g, x1, y1 = extended_gcd(b % a, a)

    x = y1 - (b // a) * x1
    y = x1

    return g, x, y


def mod_inverse(a, m):
    """
    Computes modular inverse:
        a^-1 mod m
    """
    g, x, _ = extended_gcd(a, m)

    if g != 1:
        raise ValueError("Modular inverse does not exist")

    return x % m



def miller_rabin(n, rounds=20):
    """
    Probabilistic primality test
    """

    if n < 2:
        return False

    if n in (2, 3):
        return True

    if n % 2 == 0:
        return False

   
    r = 0
    d = n - 1

    while d % 2 == 0:
        r += 1
        d //= 2

    for _ in range(rounds):

       
        a = secrets.randbelow(n - 3) + 2

        x = mod_pow(a, d, n)

        if x == 1 or x == n - 1:
            continue

        for _ in range(r - 1):

            x = mod_pow(x, 2, n)

            if x == n - 1:
                break

        else:
            return False

    return True




def generate_prime(bits):
    """
    Generate random prime number
    """

    while True:

        
        p = secrets.randbits(bits)

        p |= (1 << (bits - 1)) | 1

        if miller_rabin(p):
            return p


def generate_safe_prime(bits):
    """
    Generate safe prime:
        p = 2q + 1
    """

    print(f"[*] Generating {bits}-bit safe prime...")

    attempts = 0

    while True:

        q = generate_prime(bits - 1)
        p = 2 * q + 1

        if miller_rabin(p):

            print(f"[✓] Safe prime found after {attempts} attempts")

            return p, q

        attempts += 1




def find_primitive_root(p, q):
    """
    Find generator g
    """

    while True:

        g = secrets.randbelow(p - 3) + 2

        
        if mod_pow(g, q, p) != 1 and mod_pow(g, 2, p) != 1:
            return g



def generate_keys(bits=256):
    """
    Generate ElGamal public/private keys
    """

    print("\n[*] Key Generation")

    p, q = generate_safe_prime(bits)

    g = find_primitive_root(p, q)

    
    x = secrets.randbelow(p - 3) + 2

   
    y = mod_pow(g, x, p)

    public_key = (p, g, y)
    private_key = (p, g, x)

    print(f"\np = {p}")
    print(f"g = {g}")
    print(f"y = {y}")
    print(f"x = {x} (PRIVATE)")

    return public_key, private_key




def encrypt(public_key, plaintext_int):
    """
    Encrypt integer message
    """

    p, g, y = public_key

    if not (0 < plaintext_int < p):
        raise ValueError("Message must satisfy 0 < m < p")

    
    k = secrets.randbelow(p - 3) + 2

    
    c1 = mod_pow(g, k, p)

    
    s = mod_pow(y, k, p)

    
    c2 = (plaintext_int * s) % p

    return (c1, c2)



def decrypt(private_key, ciphertext):
    """
    Decrypt ciphertext
    """

    p, g, x = private_key

    c1, c2 = ciphertext

   
    s = mod_pow(c1, x, p)

    
    s_inv = mod_inverse(s, p)

    m = (c2 * s_inv) % p

    return m




def str_to_int(s):
    return int(s.encode("utf-8").hex(), 16)


def int_to_str(n):

    h = hex(n)[2:]

    if len(h) % 2:
        h = "0" + h

    return bytes.fromhex(h).decode("utf-8")



def demo():

    print("=" * 60)
    print("      Secure ElGamal Encryption Demo")
    print("=" * 60)

    
    public_key, private_key = generate_keys(bits=256)

    p, g, y = public_key

    
    message = "Hello ElGamal"

    print(f"\nOriginal Message:")
    print(message)

    m = str_to_int(message)

    print(f"\nMessage Integer:")
    print(m)

    if m >= p:
        raise ValueError("Message too large for current key size")

    ciphertext = encrypt(public_key, m)

    print("\nCiphertext:")
    print(f"c1 = {ciphertext[0]}")
    print(f"c2 = {ciphertext[1]}")


    recovered_int = decrypt(private_key, ciphertext)

    recovered_message = int_to_str(recovered_int)

    print("\nRecovered Message:")
    print(recovered_message)

   
    if recovered_message == message:
        print("\n[✓] Decryption successful")
    else:
        print("\n[✗] Decryption failed")


if __name__ == "__main__":
    demo()