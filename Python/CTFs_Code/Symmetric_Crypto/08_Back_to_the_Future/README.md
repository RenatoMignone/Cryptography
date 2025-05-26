## Challenge Description

This challenge presents a web application that uses the ChaCha20 stream cipher to encrypt session cookies. The application allows users to log in and, if they are an admin, access a secret flag. The encryption key is stored in the session and reused for both encryption and decryption of cookies within the same session.

## Vulnerability

The main vulnerability in the challenge is the reuse of the ChaCha20 keystream for encrypting cookies. Since the key is stored in the session and the nonce is provided to the user, an attacker can obtain both the ciphertext and the corresponding plaintext (by knowing the structure and values of the cookie after login). This allows the attacker to recover the keystream used for encryption.

## Attack Used: Keystream Reuse Attack

ChaCha20 is a stream cipher, and its security relies on never reusing the same keystream for different plaintexts. If the same key and nonce are used, the keystream will be the same, and XORing the ciphertext with the known plaintext reveals the keystream. With the keystream, an attacker can forge arbitrary cookies by XORing the desired plaintext with the recovered keystream, producing a valid ciphertext for the server to decrypt.

## Exploitation Steps

1. **Initial Login**: The attacker logs in as an admin (admin=1) and receives an encrypted cookie and the nonce. The attacker knows the structure and values of the plaintext cookie.
2. **Keystream Recovery**: By XORing the known plaintext with the received ciphertext, the attacker recovers the keystream used by ChaCha20.
3. **Cookie Forgery**: The attacker crafts a new cookie with a forged expiration date that satisfies the server's admin validation logic. The attacker XORs this new plaintext with the recovered keystream to produce a valid ciphertext.
4. **Flag Retrieval**: The attacker sends the forged ciphertext and nonce to the `/flag` endpoint. If the forged expiration date is within the required range, the server grants admin access and returns the flag.

## Solution

The provided `solve.py` script automates this attack:
- It logs in as admin to obtain the keystream.
- It brute-forces possible expiration dates to satisfy the server's time checks.
- It forges cookies and submits them to the server until the flag is returned.

**In summary:**  
The challenge demonstrates the dangers of keystream reuse in stream ciphers. By reusing the same key and nonce for multiple encryptions, the application allows attackers to recover the keystream and forge arbitrary encrypted data, leading to privilege escalation and flag retrieval.
