#Read and understand the code. You'll easily find a way to forge the target cookie.
#nc 130.192.5.212 6521

#FLAG: CRYPTO25{7d3060b2-518e-4f58-a277-7c5f5d6e11ec}

import base64
import json

def xor(a, b):
    return bytes([x ^ y for x, y in zip(a, b)])

# Original token from the server
token = "vTtvyreAr+qijt6B.KzkHzCFJU0Ue0cpaea/QqVnRhM+UwQ=="
nonce_b64, ciphertext_b64 = token.split(".")
nonce = base64.b64decode(nonce_b64)
ciphertext = base64.b64decode(ciphertext_b64)

# Known plaintext that was encrypted originally
original_plaintext = json.dumps({"username": "Renato"}).encode()

# Recover the keystream
keystream = xor(original_plaintext, ciphertext)

# New desired plaintext (shorter or equal to original length!)
target_data = json.dumps({"admin": True}).encode()

# If it's longer than the original plaintext, it won't work (keystream too short)
if len(target_data) > len(keystream):
    raise ValueError("New plaintext is too long for existing keystream!")

# Encrypt: ciphertext = plaintext ⊕ keystream
forged_ciphertext = xor(target_data, keystream[:len(target_data)])

# Forge the token
forged_token = base64.b64encode(nonce).decode() + "." + base64.b64encode(forged_ciphertext).decode()
print(f"Forged admin token: {forged_token}")