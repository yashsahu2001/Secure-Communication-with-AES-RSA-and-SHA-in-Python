# Secure-Communication-with-AES-RSA-and-SHA-in-Python

## Features
🔐 Symmetric Encryption (AES): Implements AES-GCM, an authenticated encryption (AEAD) mode that provides both confidentiality and integrity.

🔑 Asymmetric Cryptography (RSA):

Encryption: Uses RSA with OAEP padding, the current industry standard for secure encryption.

Digital Signatures: Uses RSA with PSS padding to securely sign and verify data.

#️⃣ Cryptographic Hashing (SHA): Demonstrates secure hashing with SHA-2 (SHA-256, SHA-512) and SHA-3 (SHA3-256) using Python's native hashlib library.

🚀 Ready-to-Run: A single script with minimal setup designed to work directly in environments like VS Code.

## Requirements
Python (version 3.7 or newer)

pycryptodome library

## Setup and Installation
Follow these steps to get the project running on your local machine.

1. Clone the repository:

``` 
git clone https://github.com/yashsahu2001/Secure-Communication-with-AES-RSA-and-SHA-in-Python.git
 ```
  
``` 
cd your-repository-name
```

2. Install the required package:

Run this command in your terminal to install pycryptodome:

``` 
pip install pycryptodome
```

## Usage
The crypto_demo.py script contains all the examples. To run it, simply execute the file from your terminal:

``` 
python crypto_demo.py
```

You will see output demonstrating the successful execution of each cryptographic function.

### Expected Output

```
 === AES DEMO ===
Ciphertext: 45f3...
Decrypted: Secret message for AES-GCM

=== RSA DEMO ===
RSA Ciphertext: 89af23c7...
Decrypted: RSA Encryption Example
Signature (first 60 hex chars): 38a1d9...
Signature verification: SUCCESS

=== SHA DEMO ===
SHA-256: 93d7...
SHA-512: 41e8...
SHA3-256: 6d0f...
```


Note: The hexadecimal outputs for ciphertext and signatures will be different each time you run the script, as new random keys are generated.

## Code Overview
The script is organized into modular functions for clarity:

aes_demo():

Generates a random 256-bit AES key and a nonce.

Encrypts a plaintext message using AES-GCM, producing ciphertext and an authentication tag.

Decrypts the ciphertext and verifies the tag to ensure data integrity.

rsa_demo():

Generates a 2048-bit RSA key pair.

Encrypts a message with the public key using OAEP padding.

Decrypts the message with the private key.

Signs a hash of the message with the private key using PSS padding.

Verifies the signature with the public key.

sha_demo():

Demonstrates creating cryptographic hashes of a piece of data using three different standard algorithms from the SHA family.

## Future Enhancements
This project serves as a foundation. Future improvements could include:

Hybrid Encryption: Implement a full workflow combining RSA and AES for encrypting large files efficiently.

Key Management: Add functions to securely save keys to .pem files and load them for reuse.

Error Handling: Expand try...except blocks to demonstrate failures, such as an AES authentication tag mismatch.

## License
This project is licensed under the MIT License
