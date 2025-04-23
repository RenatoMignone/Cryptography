#Read and understand the code. You'll easily find a way to forge the target cookie.
#nc 130.192.5.212 6521

#################################################################################
#FLAG: CRYPTO25{7d3060b2-518e-4f58-a277-7c5f5d6e11ec}
#################################################################################

import base64  # Import base64 for encoding/decoding
import json    # Import json for handling JSON data

def xor(a, b):
    return bytes([x ^ y for x, y in zip(a, b)])  # XOR two byte strings

# Original token from the server
token = "vTtvyreAr+qijt6B.KzkHzCFJU0Ue0cpaea/QqVnRhM+UwQ=="     # The token to be forged

# The token is base64 encoded, split into nonce and ciphertext as defined by the server 
nonce_b64, ciphertext_b64 = token.split(".")                    # Split token into nonce and ciphertext (base64)
nonce = base64.b64decode(nonce_b64)                             # Decode nonce from base64
ciphertext = base64.b64decode(ciphertext_b64)                   # Decode ciphertext from base64

# Known plaintext that was encrypted originally
original_plaintext = json.dumps({"username": "Renato"}).encode()  # The original JSON plaintext

# Recover the keystream
# Since we already know both the plaintext and the ciphertext, we can recreate the keystream
keystream = xor(original_plaintext, ciphertext)  # Derive keystream by XORing plaintext and ciphertext

# New desired plaintext (shorter or equal to original length!)
# Ad done in the server, we define a new JSON with the admin entry, setting it as true
target_data = json.dumps({"admin": True}).encode()  # The new JSON data to forge

# Encrypt: ciphertext = plaintext ⊕ keystream
# So the new cookie will be created now
forged_ciphertext = xor(target_data, keystream[:len(target_data)])  # Encrypt new data with keystream

# Forge the token
# The new token is built by concatenating the nonce and the new ciphertext
# The nonce remains the same, but the ciphertext is the new one
forged_token = base64.b64encode(nonce).decode() + "." + base64.b64encode(forged_ciphertext).decode()  # Build new token
print(f"Forged admin token: {forged_token}")  # Output the forged token