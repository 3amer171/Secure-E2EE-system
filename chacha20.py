import struct
import secrets


def to_bytes(data):
    return data.encode("utf-8") if isinstance(data, str) else data


def words_to_bytes(words):
    return b"".join(struct.pack("<I", w) for w in words)


def bytes_to_words(data):
    return list(struct.unpack_from("<" + "I" * (len(data) // 4), data))


CONSTANTS = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]


def generate_key():
    return bytes(secrets.randbits(8) for _ in range(32))


def generate_nonce():
    return bytes(secrets.randbits(8) for _ in range(12))


def build_state(key, counter, nonce):
    key_words = bytes_to_words(key)
    nonce_words = bytes_to_words(nonce)
    return [
        CONSTANTS[0], CONSTANTS[1], CONSTANTS[2], CONSTANTS[3],
        key_words[0], key_words[1], key_words[2], key_words[3],
        key_words[4], key_words[5], key_words[6], key_words[7],
        counter, nonce_words[0], nonce_words[1], nonce_words[2],
    ]


MASK32 = 0xFFFFFFFF


def rotl32(v, n):
    return ((v << n) | (v >> (32 - n))) & MASK32


def quarter_round(a, b, c, d):
    a = (a + b) & MASK32; d ^= a; d = rotl32(d, 16)
    c = (c + d) & MASK32; b ^= c; b = rotl32(b, 12)
    a = (a + b) & MASK32; d ^= a; d = rotl32(d, 8)
    c = (c + d) & MASK32; b ^= c; b = rotl32(b, 7)
    return a, b, c, d


def double_round(s):
    s[0], s[4], s[8],  s[12] = quarter_round(s[0], s[4], s[8],  s[12])
    s[1], s[5], s[9],  s[13] = quarter_round(s[1], s[5], s[9],  s[13])
    s[2], s[6], s[10], s[14] = quarter_round(s[2], s[6], s[10], s[14])
    s[3], s[7], s[11], s[15] = quarter_round(s[3], s[7], s[11], s[15])
    s[0], s[5], s[10], s[15] = quarter_round(s[0], s[5], s[10], s[15])
    s[1], s[6], s[11], s[12] = quarter_round(s[1], s[6], s[11], s[12])
    s[2], s[7], s[8],  s[13] = quarter_round(s[2], s[7], s[8],  s[13])
    s[3], s[4], s[9],  s[14] = quarter_round(s[3], s[4], s[9],  s[14])


def generate_keystream_block(key, counter, nonce):
    initial = build_state(key, counter, nonce)
    working = initial[:]
    for _ in range(10):
        double_round(working)
    output = [(working[i] + initial[i]) & MASK32 for i in range(16)]
    return words_to_bytes(output)


def chacha20_process(data, key, nonce, counter=0):
    output = bytearray()
    for block_idx in range(0, len(data), 64):
        keystream = generate_keystream_block(key, counter + block_idx // 64, nonce)
        chunk = data[block_idx:block_idx + 64]
        for i in range(len(chunk)):
            output.append(chunk[i] ^ keystream[i])
    return bytes(output)


def encrypt(data, key, nonce):
    return chacha20_process(to_bytes(data), key, nonce)


def decrypt(data, key, nonce):
    return chacha20_process(data, key, nonce)


def encrypt_file(input_file, output_file, key, nonce):
    with open(input_file, "rb") as f:
        file_data = f.read()
    encrypted = encrypt(file_data, key, nonce)
    with open(output_file, "wb") as f:
        f.write(nonce + encrypted)


def decrypt_file(input_file, output_file, key):
    with open(input_file, "rb") as f:
        data = f.read()
    nonce = data[:12]
    ciphertext = data[12:]
    decrypted = decrypt(ciphertext, key, nonce)
    with open(output_file, "wb") as f:
        f.write(decrypted)


if __name__ == "__main__":
    key = generate_key()
    nonce = generate_nonce()
    input_file = "sensors.pdf"
    encrypt_file(input_file, "encrypted.bin", key, nonce)
    decrypt_file("encrypted.bin", "restored.pdf", key)
    print("Encryption + Decryption completed successfully.")
