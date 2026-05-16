# Secure-E2EE-system


System Components

CA (ca1.py) — Certificate Authority. Runs first. Issues and signs identity certificates for both users.
User X (x1.py) — Host. Listens for incoming peer connections.
User Y (y1.py) — Client. Connects to X to start the chat.


Cryptographic Algorithms Used
AlgorithmPurposeECDSAIdentity certificates, message signingElGamalAsymmetric session key transportChaCha20Symmetric message encryptionBlowfishLocal chat history encryption at restSHA-256Vault password key derivation

Startup

CA launches and loads its ECDSA keypair. Listens on port 5000.
X launches, types vault password, generates ElGamal + ECDSA keypairs, requests certificate from CA.
Y launches, types vault password, generates ElGamal + ECDSA keypairs in background thread, requests certificate from CA.
CA signs each certificate binding the user's identity, ElGamal public key, and ECDSA public key together with a 1 hour expiry.
Both users store their certificate. Connect button on Y enables when ready.


Handshake (when Y clicks Connect)

Y connects to X on port 6001.
X sends its CA-signed certificate to Y.
Y verifies X's certificate signature against the hardcoded CA public key and checks expiry. If it fails the connection is dropped.
Y sends its CA-signed certificate to X.
X verifies Y's certificate the same way.
Both sides extract and store the peer's ECDSA public key from the certificate — this is the key that will be used to verify all future messages.
X generates a random 32-byte ChaCha20 session key.
X encrypts the session key as an integer using Y's ElGamal public key from the certificate.
X sends the ElGamal ciphertext (c1, c2) to Y.
Y decrypts it using its own ElGamal private key, recovers the session key.
Both sides now share the same session key. Tunnel is active.


Sending a Message

Sender builds a JSON package containing message type, content, message ID, and timestamp.
A fresh random nonce is generated.
The package is encrypted with ChaCha20 using the current session key and nonce.
The package is signed with the sender's ECDSA private key.
The wire packet sent is: {nonce, encrypted_payload, signature} — plaintext never touches the network.
Receiver decrypts the payload using the session key and nonce.
Receiver verifies the signature using the sender's ECDSA public key extracted from the CA certificate during handshake — not from the packet itself.
If verification fails the message is dropped and a security error is logged.
If it passes the message is displayed and saved to the local .bin history file encrypted with Blowfish.


Key Rotation (every 60 seconds)

X's timer fires automatically.
X generates a brand new random 32-byte session key.
X ElGamal-encrypts the new key using Y's public key.
X wraps it in a key_rotation control message, encrypts it with the current session key, and signs it with its ECDSA private key.
X sends it to Y and immediately switches to the new key locally.
Y receives it, decrypts the outer packet with the current session key, verifies the signature, then ElGamal-decrypts the inner payload to recover the new key.
Y switches to the new key.
The old key is discarded from memory. Any previously recorded traffic encrypted under it cannot be decrypted even if the current key is later compromised.


Local Chat History

Every message sent and received is saved to a local .bin file.
Records are encrypted with Blowfish before writing using a key derived from the user's vault password via SHA-256.
The password is never stored — it is typed at launch and derived in memory only.
Without the correct password the .bin file is unreadable.


Security Properties

Confidentiality — all messages are ChaCha20 encrypted on the wire
Integrity — all messages are ECDSA signed, tampered messages are dropped
Authentication — signing keys are bound to CA-verified identities, no self-reported keys are trusted
Forward secrecy — session key rotates every 60 seconds, old keys are discarded
At-rest protection — local history encrypted with a password-derived Blowfish key



HOW TO RUN 

1. python ca1.py        ← start CA first
2. python x1.py         ← start User X, enter vault password
3. python y1.py         ← start User Y, enter vault password, wait for keys, click Connect