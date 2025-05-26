## Challenge Description

This challenge presents a cryptographic oracle that, for each round, randomly selects either AES-ECB or AES-CBC mode to encrypt user-supplied data. The user is given a random 32-byte OTP (one-time pad), and must submit a 32-byte input (as hex) to the server. The server XORs the input with the OTP, encrypts it using the randomly chosen mode, and returns the ciphertext. The user must then guess which mode was used. This process is repeated for 128 rounds; if all guesses are correct, the flag is revealed.

## Attack Used

The attack exploits the fundamental difference between ECB (Electronic Codebook) and CBC (Cipher Block Chaining) modes:

- **ECB Mode:** Identical plaintext blocks are encrypted to identical ciphertext blocks.
- **CBC Mode:** Each plaintext block is XORed with the previous ciphertext block (or IV for the first block), so identical plaintext blocks will almost never produce identical ciphertext blocks.

This property allows an attacker to distinguish between ECB and CBC by submitting input with repeated blocks and observing the ciphertext.

## Solution Approach

1. **Input Crafting:** The attacker crafts a 32-byte input consisting of two identical 16-byte blocks (e.g., all zeros).
2. **XOR with OTP:** The server XORs this input with the OTP, resulting in two blocks that are identical to each other (since XOR with the same value preserves equality).
3. **Encryption:** The server encrypts the result using either ECB or CBC.
4. **Ciphertext Analysis:** 
    - If the ciphertext's two blocks are identical, ECB was used.
    - If the ciphertext's two blocks differ, CBC was used.
5. **Automated Guessing:** The solution script automates this process, sending the crafted input, analyzing the ciphertext, and submitting the correct guess for each round.

## Exploiting the Vulnerability

The vulnerability lies in the use of ECB mode, which leaks information about repeated plaintext blocks. By leveraging this, the attacker can reliably distinguish ECB from CBC, defeating the intended secrecy of the mode selection.

## Summary

- **Vulnerability:** ECB mode leaks block equality.
- **Attack:** Submit repeated blocks, observe ciphertext equality.
- **Result:** Mode can be distinguished with probability 1, allowing the attacker to win the challenge and obtain the flag.
