## Challenge Description

This challenge provides a remote encryption oracle that appends a secret flag to any user-supplied input, encrypts the result using AES in ECB mode, and returns the ciphertext. The user can interact with the service by sending hex-encoded plaintexts and receiving the corresponding ciphertexts.

## Vulnerability

The main vulnerability is the use of AES in ECB (Electronic Codebook) mode. ECB deterministically encrypts identical plaintext blocks into identical ciphertext blocks, leaking information about the plaintext structure. Additionally, the service appends the secret flag to user input before encryption, allowing an attacker to control the prefix of the plaintext.

## Attack Used

**Attack Name:** Adaptive Chosen Plaintext Attack (Byte-at-a-time ECB Oracle Attack)

**How the Attack Works:**
- The attacker sends carefully crafted plaintexts to the oracle, observing how the ciphertext changes.
- By aligning the unknown flag byte at the end of a block, the attacker can guess its value by brute-forcing all possible bytes and comparing the resulting ciphertext block with the oracle's response.
- This process is repeated byte by byte, gradually recovering the entire secret flag.

## Solution Approach

The provided `solve.py` script automates the byte-at-a-time ECB oracle attack:
1. It connects to the remote service and determines the expected flag length.
2. For each byte of the flag, it sends a prefix of 'A's to align the next unknown flag byte at the end of a block.
3. It then tries all possible byte values for the next flag character, appending each guess to the known prefix and recovered bytes.
4. For each guess, it compares the ciphertext block with the oracle's response. When a match is found, the correct byte is recovered.
5. This process is repeated until the entire flag is revealed.

## Exploitation Steps

1. **Control the Prefix:** By sending varying lengths of 'A's, the attacker can control the alignment of the unknown flag bytes within the ciphertext blocks.
2. **Oracle Queries:** For each position, the attacker queries the oracle with all possible byte values for the next flag character.
3. **Block Comparison:** The attacker compares the ciphertext blocks to identify the correct byte.
4. **Iterative Recovery:** The process is repeated for each byte until the full flag is recovered.

## Summary

This challenge demonstrates the dangers of using ECB mode for encryption, especially when user-controlled input is concatenated with secret data. The byte-at-a-time ECB oracle attack allows an attacker to fully recover the secret flag by exploiting the deterministic nature of ECB encryption.
