## Challenge Description

This challenge implements a token-based authentication system using the ChaCha20 stream cipher. When a user provides their name, the server generates a token by encrypting a JSON object containing the username with ChaCha20, using a randomly generated key and nonce. The token is then provided to the user in the form of two base64-encoded parts: the nonce and the ciphertext.

To access the flag, a user must present a token that, when decrypted, contains `"admin": true` in the JSON object.

## Vulnerability

The main vulnerability in the challenge is the reuse of the same nonce and key when decrypting tokens. While the server generates a random nonce for each token it issues, it accepts any token for verification, including those with reused nonces. This allows an attacker to exploit the properties of stream ciphers: if the same nonce and key are used, the keystream is the same, and knowing one plaintext-ciphertext pair allows the attacker to forge new valid ciphertexts for the same nonce.

## Attack Used: Key Stream Reuse Attack

The attack leverages the fact that ChaCha20 is a stream cipher, and encrypting two different plaintexts with the same key and nonce produces ciphertexts that can be manipulated if one plaintext is known. Specifically, if an attacker knows the plaintext and the ciphertext for a given nonce, they can recover the keystream and use it to encrypt any other plaintext of their choice.

## Exploitation Steps

1. **Obtain a Token:** The attacker requests a token for a known username (e.g., `"Renato"`). The server returns a token containing the base64-encoded nonce and ciphertext.
2. **Recover the Keystream:** Since the attacker knows the plaintext (the JSON with their username) and the ciphertext, they can XOR them to recover the keystream used for encryption.
3. **Forge a New Token:** The attacker creates a new JSON object with `"admin": true`, encodes it, and XORs it with the recovered keystream to produce a forged ciphertext.
4. **Build the Forged Token:** The attacker constructs a new token using the original nonce and the forged ciphertext, both base64-encoded.
5. **Submit the Forged Token:** When this forged token is submitted to the server, it decrypts to a JSON object with `"admin": true`, granting admin access and revealing the flag.

## Solution Script

The provided `solve.py` script automates these steps:
- It takes the original token, splits and decodes the nonce and ciphertext.
- It reconstructs the original plaintext.
- It recovers the keystream by XORing the known plaintext and ciphertext.
- It forges a new ciphertext for the admin JSON.
- It outputs a valid forged token that can be used to obtain the flag.

## Summary

This challenge demonstrates the dangers of nonce reuse in stream ciphers. By reusing a nonce with the same key, the system allows attackers to recover the keystream and forge arbitrary valid tokens, completely breaking the authentication mechanism.
