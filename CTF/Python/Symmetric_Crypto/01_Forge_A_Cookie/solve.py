#################################################################################
#Read and understand the code. You'll easily find a way to forge the target cookie.
#nc 130.192.5.212 6521

#################################################################################
#FLAG: CRYPTO25{7d3060b2-518e-4f58-a277-7c5f5d6e11ec}
#################################################################################

#################################################################################
# Attack: Key Stream Reuse
#################################################################################

import base64 
import json  

def xor(a, b):
    return bytes([x ^ y for x, y in zip(a, b)])

# Original token from the server
token = "UOsa8+NYOydRMYWT.9HS+KxnSpYiraDfNCTC828t9MEQDsPaLiF4=" 

# The token is base64 encoded, split into nonce and ciphertext as defined by the server 
nonce_b64, ciphertext_b64 = token.split(".")           

# Decode
nonce = base64.b64decode(nonce_b64)                             
ciphertext = base64.b64decode(ciphertext_b64)                  

# Known plaintext that was encrypted originally
# Same structure as the one used in the server
original_plaintext = json.dumps({"username": "Renato"}).encode()  


# Since we already know both the plaintext and the ciphertext, we can recreate the keystream
keystream = xor(original_plaintext, ciphertext)

# New desired plaintext
target_data = json.dumps({"admin": True}).encode()  # The new JSON data to forge

# Encrypt: ciphertext = plaintext ⊕ keystream
# So the new cookie will be created now
forged_ciphertext = xor(target_data, keystream[:len(target_data)])  # Encrypt new data with keystream


# The new token is built by concatenating the nonce and the new ciphertext
# The nonce remains the same, but the ciphertext is the new one
forged_token = base64.b64encode(nonce).decode() + "." + base64.b64encode(forged_ciphertext).decode()
print(f"Forged admin token: {forged_token}") 