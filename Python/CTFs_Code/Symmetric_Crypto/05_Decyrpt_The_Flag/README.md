## Challenge Description

This challenge implements a simple encryption service using the ChaCha20 stream cipher. The user is asked to provide a seed to initialize the random number generator, which is then used to generate a random nonce. The service encrypts a secret flag using this nonce and a fixed key, and then allows the user to encrypt arbitrary messages. However, the nonce is not properly updated between encryptions, leading to a critical vulnerability.

## Vulnerability

The main vulnerability is the reuse of the same nonce and key for multiple encryptions. In stream ciphers like ChaCha20, reusing the same nonce and key combination results in the reuse of the keystream. This allows an attacker to perform a known-plaintext or chosen-plaintext attack to recover the original plaintexts.

## Attack Used

**Key Stream Reuse Attack (Known-Plaintext/Chosen-Plaintext Attack):**

When the same nonce and key are used, encrypting two different plaintexts produces two ciphertexts that can be XORed together to reveal information about the plaintexts. If one plaintext is known or controlled, the other can be recovered.

## Exploitation

To exploit this vulnerability, the attacker:
1. Connects to the service and provides a seed (e.g., 0) to ensure deterministic nonce generation.
2. Receives the ciphertext of the secret flag.
3. Requests encryption of a known plaintext (e.g., a string of 'A's of the same length as the flag).
4. Receives the ciphertext of the known plaintext.
5. XORs the flag ciphertext, the known ciphertext, and the known plaintext to recover the flag.

This works because:
```
flag_ctxt = flag ^ keystream
known_ctxt = known ^ keystream
flag = flag_ctxt ^ known_ctxt ^ known
```

## Solution

The provided `solve.py` script automates this attack by:
- Connecting to the service,
- Sending a seed,
- Receiving the encrypted flag,
- Sending a known plaintext,
- Receiving its ciphertext,
- XORing the results to recover the flag.

This demonstrates the importance of never reusing a nonce with the same key in stream cipher encryption.
