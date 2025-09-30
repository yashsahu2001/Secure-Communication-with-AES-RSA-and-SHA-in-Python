from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Signature import pss
from Crypto.Hash import SHA256
import hashlib


# =============== AES EXAMPLE (AES-GCM) ===============
def aes_demo():
    print("\n=== AES DEMO ===")
    key = get_random_bytes(32)  # AES-256
    nonce = get_random_bytes(12)

    plaintext = b"Secret message for AES-GCM"
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    print("Ciphertext:", ciphertext.hex())

    # Decrypt
    dec = AES.new(key, AES.MODE_GCM, nonce=nonce)
    decrypted = dec.decrypt_and_verify(ciphertext, tag)
    print("Decrypted:", decrypted.decode())


# =============== RSA EXAMPLE (OAEP + PSS) ===============
def rsa_demo():
    print("\n=== RSA DEMO ===")
    key = RSA.generate(2048)
    private_key = key
    public_key = key.publickey()

    # Encrypt with OAEP
    message = b"RSA Encryption Example"
    cipher_rsa = PKCS1_OAEP.new(public_key)
    ciphertext = cipher_rsa.encrypt(message)
    print("RSA Ciphertext:", ciphertext.hex()[:60], "...")

    # Decrypt with OAEP
    decipher_rsa = PKCS1_OAEP.new(private_key)
    decrypted = decipher_rsa.decrypt(ciphertext)
    print("Decrypted:", decrypted.decode())

    # Sign with PSS
    h = SHA256.new(message)
    signer = pss.new(private_key)
    signature = signer.sign(h)
    print("Signature (first 60 hex chars):", signature.hex()[:60], "...")

    # Verify
    verifier = pss.new(public_key)
    try:
        verifier.verify(h, signature)
        print("Signature verification: SUCCESS")
    except (ValueError, TypeError):
        print("Signature verification: FAILED")


# =============== SHA HASHING DEMO ===============
def sha_demo():
    print("\n=== SHA DEMO ===")
    data = b"Hash this data"
    print("SHA-256:", hashlib.sha256(data).hexdigest())
    print("SHA-512:", hashlib.sha512(data).hexdigest())
    print("SHA3-256:", hashlib.sha3_256(data).hexdigest())


# Run all demos
if __name__ == "__main__":
    aes_demo()
    rsa_demo()
    sha_demo()