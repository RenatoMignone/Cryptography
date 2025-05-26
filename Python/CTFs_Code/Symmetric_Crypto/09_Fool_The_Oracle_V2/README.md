## Challenge Description

This challenge implements an AES encryption oracle in ECB mode. The server takes user input (as hex), prepends a random 5-byte prefix, appends a secret flag, pads the result, and encrypts everything with AES-ECB using a random 24-byte key. The user can repeatedly submit plaintexts and receive the corresponding ciphertexts.

## Vulnerability

The main vulnerability is the use of AES in ECB mode, which deterministically encrypts identical plaintext blocks to identical ciphertext blocks. The server also prepends a fixed-length random prefix and appends the flag, but the prefix length is constant for a session. This setup is susceptible to a byte-at-a-time chosen-plaintext attack, even with the random prefix.

## Attack Used

**Adaptive Chosen Plaintext Attack (Byte-at-a-Time ECB Decryption with Random Prefix):**

1. **Alignment Discovery:**  
   The attacker sends varying-length inputs to determine how many bytes are needed to align their controlled input with a block boundary after the random prefix. This is done by looking for two identical adjacent ciphertext blocks, which only occurs when the attacker's input is block-aligned.

2. **Byte-at-a-Time Decryption:**  
   Once alignment is found, the attacker crafts inputs so that each unknown byte of the flag appears at the end of a block. By submitting all possible byte values and comparing the resulting ciphertext blocks, the attacker can recover the flag one byte at a time.

## Exploitation Steps

- The attacker first determines the required padding to align their input after the random prefix.
- For each byte of the flag, the attacker:
  - Crafts a plaintext that positions the next unknown flag byte at the end of a block.
  - Submits all possible byte values for that position.
  - Compares the ciphertext blocks to find the correct byte value.
- This process is repeated until the entire flag is recovered.

## Solution

The provided `solve.py` script automates this attack:
- It finds the alignment using repeated queries.
- It then recovers the flag byte-by-byte using the ECB oracle, exploiting the deterministic nature of ECB mode and the fixed random prefix length.

**In summary:**  
The challenge demonstrates why ECB mode should not be used for encrypting data with predictable or repeated patterns, especially when user input is involved. The attack leverages ECB's blockwise determinism and the ability to align input after a fixed random prefix to fully recover the secret flag.
