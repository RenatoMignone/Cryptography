# Import the os module for generating random bytes
import os
# Import ChaCha20 cipher from PyCryptodome
from Crypto.Cipher import ChaCha20

# Generate a random 32-byte key for ChaCha20 encryption
key = os.urandom(32)
# Generate a random 12-byte nonce for ChaCha20 encryption
nonce = os.urandom(12)
# Print the key and nonce in hexadecimal format for reference
print(f"Using key: {key.hex()}, nonce: {nonce.hex()}")

# Open the file 'hacker-manifesto.txt' and read all lines into a list
with open("./hacker-manifesto.txt") as f:
    lines = f.readlines()

# Initialize an empty list to store encrypted lines
enc = []

# For each line in the input file
for line in lines:
    # Create a new ChaCha20 cipher object with the same key and nonce
    cipher = ChaCha20.new(key=key, nonce=nonce)
    # Encrypt the line (as bytes) and append the hex-encoded ciphertext to the list
    enc.append(cipher.encrypt(line.encode()).hex())

# Open the output file for writing encrypted lines
with open("./hacker-manifesto.enc", "w") as f:
    # Write all encrypted lines to the file, separated by newlines
    f.write("\n".join(enc))
