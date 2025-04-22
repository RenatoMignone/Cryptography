# Import os module for environment variable configuration
import os
os.environ['PWNLIB_NOTERM'] = 'True'  # Configuration patch to allow pwntools to be run inside of an IDE
os.environ['PWNLIB_SILENT'] = 'True'

# Import pwntools for remote connection
from pwn import *
# Import ceil function for padding calculation
from math import ceil
# Import AES cipher for block size constant
from Crypto.Cipher import AES

# Import host and port configuration
from myconfig import HOST,PORT

#----------------------------------------------------------
# Set AES block size in bytes
BLOCK_SIZE = AES.block_size
# Set AES block size in hex characters
BLOCK_SIZE_HEX = 2*BLOCK_SIZE

#----------------------------------------------------------
# Connect to the server at HOST:PORT
server = remote(HOST, PORT)

# stole from the server code...
# message = "This is what I received: " + msg + " -- END OF MESSAGE"
start_str = "This is what I received: "

# print(len(start_str))

# Calculate padding needed to align with block size
# This is computed by taking the length of start_str, dividing it by BLOCK_SIZE,
# and rounding up to the nearest whole number, then multiplying by BLOCK_SIZE
# to get the total length, and subtracting the length of start_str

# This line calculates how many extra bytes you need to add
# to the string start_str to make its length a multiple of BLOCK_SIZE.
pad_len = ceil(len(start_str)/BLOCK_SIZE)*BLOCK_SIZE-len(start_str)

# Construct message with enough 'A's to fill two blocks after the prefix
msg = b"A"*(16*2+pad_len) #2 * AES.block_size + oad_len
print("Sending: "+str(msg))
# Send the crafted message to the server
server.send(msg)

# Receive the ciphertext from the server
ciphertext = server.recv(1024)
# Convert ciphertext to hexadecimal string
ciphertext_hex = ciphertext.hex()
print(ciphertext_hex)

# Close the connection to the server
server.close()

#----------------------------------------------------------
# Print each ciphertext block in hex
for i in range(0,int(len(ciphertext_hex)//BLOCK_SIZE_HEX)):
    print(ciphertext_hex[i*BLOCK_SIZE_HEX:(i+1)*BLOCK_SIZE_HEX])

# Detect mode by comparing ciphertext blocks
print("Selected mode is", end=' ')
# This checks if two adjacent 16-byte blocks in the ciphertext are identical.
if ciphertext[2*BLOCK_SIZE:3*BLOCK_SIZE] == ciphertext[3*BLOCK_SIZE:4*BLOCK_SIZE] :
    print("ECB")
else:
    print("CBC")
