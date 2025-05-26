## Challenge Description

This challenge presents a simple authentication system that issues an encrypted cookie to users after they provide a username. The cookie contains two fields: the username and an admin flag (set to `false` by default). The encryption mode used is AES in ECB (Electronic Codebook) mode.

To access the flag, a user must present a valid cookie where the `admin` field is set to `true`. However, the server never issues such a cookie directly.

## Vulnerability

The main vulnerability lies in the use of AES-ECB mode for encrypting the cookie. ECB mode encrypts each block of plaintext independently, so identical plaintext blocks always produce identical ciphertext blocks. This lack of diffusion allows attackers to manipulate ciphertext blocks to forge new, valid cookies.

## Attack Used

The attack used is known as the **ECB Cut-and-Paste Attack** (or Copy-and-Paste Attack). By carefully crafting the input (username), an attacker can control the alignment of values within the encrypted blocks. This allows the attacker to extract a ciphertext block corresponding to `admin=true` and splice it into a valid cookie.

## Solution Steps

1. **Craft the Username:**  
   The attacker submits a username such that when the cookie is constructed (`username=<username>&admin=false`), the value `true` is aligned at the start of a new block after `admin=`.

2. **Obtain the Encrypted Cookie:**  
   The server returns the encrypted cookie. The attacker then extracts the ciphertext block that corresponds to `admin=true` (crafted via the username input).

3. **Forge the Admin Cookie:**  
   The attacker rearranges the ciphertext blocks:  
   - The first block(s) for `username=...`  
   - The block containing `admin=true`  
   - The remaining blocks as needed  
   This creates a new ciphertext that, when decrypted by the server, results in a cookie with `admin=true`.

4. **Submit the Forged Cookie:**  
   The attacker sends the forged cookie to the server, which then grants admin access and reveals the flag.

## Exploitation Example

The provided `solve.py` script demonstrates this attack by:
- Connecting to the challenge server
- Sending a specially crafted username to align `true` at the start of a block
- Receiving the encrypted cookie
- Rearranging the ciphertext blocks to forge an admin cookie
- Submitting the forged cookie to retrieve the flag

## Summary

This challenge demonstrates the dangers of using ECB mode for encrypting structured data. ECB's deterministic and independent block encryption allows attackers to perform cut-and-paste attacks, forging valid tokens or cookies by rearranging ciphertext blocks.
