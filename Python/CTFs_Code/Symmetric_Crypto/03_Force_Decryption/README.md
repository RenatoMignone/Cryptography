## Challenge Description

This challenge implements an AES-CBC encryption/decryption service. The user can:
- Encrypt any 16-byte plaintext (except a special value called `leak`).
- Decrypt any ciphertext with a user-supplied IV (except when the IV equals `leak`).

If the decrypted plaintext matches the special value `leak` (`b"mynamesuperadmin"`), the flag is revealed.

## Vulnerability

The main vulnerability is that the user can supply both the ciphertext and the IV for decryption. In CBC mode, the first plaintext block is computed as:

```
P1 = D_K(C1) ⊕ IV
```

This means that by manipulating the IV, an attacker can control the result of the decryption, even if they cannot encrypt the forbidden value directly.

## Attack Used

**CBC Bit-Flipping Attack (IV Manipulation):**

The attacker can:
1. Encrypt any chosen 16-byte plaintext (not equal to `leak`) to obtain a ciphertext and its IV.
2. Forge a new IV so that, when decrypting the ciphertext, the output will be the forbidden `leak` value.

The forged IV is computed as:
```
forged_IV = leak ⊕ chosen_plaintext ⊕ original_IV
```
When the ciphertext is decrypted with this forged IV, the result will be `leak`, thus revealing the flag.

## Solution Steps

1. Encrypt a chosen plaintext (e.g., 16 bytes of "B") to get the ciphertext and IV.
2. Compute the forged IV using the formula above.
3. Submit the ciphertext and forged IV to the decryption function.
4. The service will decrypt the ciphertext to `leak` and print the flag.

## Exploit Script

The provided `solve.py` script automates this attack by:
- Connecting to the service.
- Encrypting a chosen plaintext.
- Calculating the forged IV.
- Sending the ciphertext and forged IV to the decryption function.
- Retrieving the flag.

## Summary

This challenge demonstrates how improper handling of IVs in CBC mode can allow attackers to control decrypted plaintexts, even bypassing restrictions on encrypting specific values. The attack leverages the malleability of CBC's IV to force decryption to a chosen value.
