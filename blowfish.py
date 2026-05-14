

import struct
import time

class Blowfish:

  
    P_INIT = [
        0x243F6A88, 0x85A308D3, 0x13198A2E,
        0x03707344, 0xA4093822, 0x299F31D0,
        0x082EFA98, 0xEC4E6C89, 0x452821E6,
        0x38D01377, 0xBE5466CF, 0x34E90C6C,
        0xC0AC29B7, 0xC97C50DD, 0x3F84D5B5,
        0xB5470917, 0x9216D5D9, 0x8979FB1B
    ]

 
    S_INIT = [
        [i * 0x01010101 & 0xFFFFFFFF for i in range(256)],
        [i * 0x02020202 & 0xFFFFFFFF for i in range(256)],
        [i * 0x03030303 & 0xFFFFFFFF for i in range(256)],
        [i * 0x04040404 & 0xFFFFFFFF for i in range(256)]
    ]

    def __init__(self, key):

        self.P = self.P_INIT[:]
        self.S = [box[:] for box in self.S_INIT]

        self.key_expansion(key)

    def F(self, x):

        a = (x >> 24) & 0xFF
        b = (x >> 16) & 0xFF
        c = (x >> 8) & 0xFF
        d = x & 0xFF

        y = (self.S[0][a] + self.S[1][b]) & 0xFFFFFFFF
        y = y ^ self.S[2][c]
        y = (y + self.S[3][d]) & 0xFFFFFFFF

        return y

    def key_expansion(self, key):

        key_bytes = key.encode()

        j = 0

        for i in range(len(self.P)):

            data = 0

            for _ in range(4):
                data = (data << 8) | key_bytes[j]
                j = (j + 1) % len(key_bytes)

            self.P[i] ^= data

    def encrypt_block(self, left, right):

        for i in range(16):

            left ^= self.P[i]
            right ^= self.F(left)

            left, right = right, left

        left, right = right, left

        right ^= self.P[16]
        left ^= self.P[17]

        return left & 0xFFFFFFFF, right & 0xFFFFFFFF

    def decrypt_block(self, left, right):

        for i in range(17, 1, -1):

            left ^= self.P[i]
            right ^= self.F(left)

            left, right = right, left

        left, right = right, left

        right ^= self.P[1]
        left ^= self.P[0]

        return left & 0xFFFFFFFF, right & 0xFFFFFFFF

    def pad(self, data):

        padding_length = 8 - (len(data) % 8)
        return data + chr(padding_length) * padding_length

  
    def unpad(self, data):

        padding_length = ord(data[-1])
        return data[:-padding_length]

 
    def encrypt(self, plaintext):

        plaintext = self.pad(plaintext)

        ciphertext = b''

        for i in range(0, len(plaintext), 8):

            block = plaintext[i:i+8].encode()

            left, right = struct.unpack(">II", block)

            left, right = self.encrypt_block(left, right)

            ciphertext += struct.pack(">II", left, right)

        return ciphertext

    def decrypt(self, ciphertext):

        plaintext = b''

        for i in range(0, len(ciphertext), 8):

            block = ciphertext[i:i+8]

            left, right = struct.unpack(">II", block)

            left, right = self.decrypt_block(left, right)

            plaintext += struct.pack(">II", left, right)

        return self.unpad(plaintext.decode())



if __name__ == "__main__":

    key = "mysecretkey"

    bf = Blowfish(key)

    plaintext = "HELLO BLOWFISH"

    print("Original Text:")
    print(plaintext)

    
    start_time = time.time()

    encrypted = bf.encrypt(plaintext)

    encryption_time = time.time() - start_time

    print("\\nEncrypted (HEX):")
    print(encrypted.hex())

  
    start_time = time.time()

    decrypted = bf.decrypt(encrypted)

    decryption_time = time.time() - start_time

    print("\\nDecrypted Text:")
    print(decrypted)

    
    print("\\nPerformance Analysis")
    print("---------------------")

    print(f"Encryption Time: {encryption_time:.6f} seconds")
    print(f"Decryption Time: {decryption_time:.6f} seconds")

    print(f"Plaintext Size: {len(plaintext.encode())} bytes")
    print(f"Ciphertext Size: {len(encrypted)} bytes")
