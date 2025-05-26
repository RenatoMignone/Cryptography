## Challenge Description

This challenge implements an AES-ECB encryption oracle. When a user provides input (as a hex string), the server concatenates a random-length random prefix, the user input, and a secret flag, then encrypts the result using AES in ECB mode with a random key and random prefix (of 1–15 bytes). The user can repeatedly query the oracle to receive ciphertexts for chosen plaintexts.

## Vulnerability

The main vulnerability is the use of AES in ECB mode, which deterministically encrypts identical plaintext blocks to identical ciphertext blocks. Additionally, the server prepends a random but fixed-length prefix to every encryption, but this prefix remains the same for the session. The flag is appended after the user input, making it possible to align user-controlled input with block boundaries after the random prefix.

## Attack Used

The attack is a **byte-at-a-time ECB decryption attack with a random-length prefix**. This is an adaptive chosen-plaintext attack that exploits the deterministic nature of ECB mode and the ability to control input alignment.

### Attack Steps

1. **Prefix Alignment:**  
   The attacker first determines the length of the random prefix by sending carefully crafted inputs (e.g., repeated 'A's) and looking for two identical consecutive ciphertext blocks. This reveals how many bytes are needed to align the start of attacker-controlled input to a block boundary.

2. **Byte-at-a-Time Decryption:**  
   Once alignment is achieved, the attacker can recover the flag one byte at a time. By submitting inputs that position the unknown flag byte at the end of a block, the attacker can brute-force all possible byte values and compare the resulting ciphertext block to the oracle's output. When a match is found, the correct byte is recovered.

3. **Iterative Recovery:**  
   This process is repeated for each byte of the flag, reconstructing the entire secret.

## Solution

The provided `solve.py` script automates this attack:
- It connects to the remote service.
- It finds the prefix alignment and block index for controlled input.
- It iteratively recovers each byte of the flag using the ECB oracle, exploiting the vulnerability described above.

## Summary

- **Vulnerability:** AES-ECB mode with a fixed random prefix and user-controlled input.
- **Attack:** Adaptive chosen-plaintext (byte-at-a-time ECB decryption with random prefix).
- **Exploit:** Align input after the random prefix, then recover the flag byte-by-byte by matching ciphertext blocks.

This demonstrates why ECB mode should not be used for encrypting data with predictable or user-controlled structure, especially when secrets are appended or prepended to user input.
