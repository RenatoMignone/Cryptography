#TRACK
#Read the code. If you really understood it, you can correctly guess the mode. 
#If you do it with a probability higher than 2^128 you'll get the flag.

#nc 130.192.5.212 6531

#################################################################################
# FLAG: CRYPTO25{3709585c-5eda-4f6a-b1e5-a93e0cf99f93}
#################################################################################

from pwn import *

# XOR function to compute the XOR of two byte sequences
def xor(a, b):
    return bytes([x ^ y for x, y in zip(a, b)])

# Establish a remote connection to the server using netcat
# The server address and port are provided in the challenge description
# the function remote is used to create a connection to the server
# it is present inside the pwn library
conn = remote('130.192.5.212', 6531)

# Loop through 128 challenges
for _ in range(128):
    # Wait for the challenge number prompt from the server
    # the function recvuntil is used to read data from the server until a specific string is found
    conn.recvuntil(f'Challenge #{_}\n'.encode())
    
    # Read the OTP (One-Time Pad) provided by the server
    # the function recvline is used to read a line of data from the server
    # the decode function is used to convert bytes to string
    # the strip function is used to remove leading and trailing whitespace
    otp_line = conn.recvline().decode().strip()

    # Extract the OTP in hexadecimal format from the received line
    otp_hex = otp_line.split(': ')[1]
    # Convert the OTP from hexadecimal string to bytes
    otp = bytes.fromhex(otp_hex)
    
    # Split the OTP into two 16-byte blocks
    # this because the OTP is 32 bytes long, so we divide it because the AES block size is 16 bytes
    otp1, otp2 = otp[:16], otp[16:]
    
    # Create a 16-byte block of zeros
    # this is used to XOR with the OTP blocks
    # the function b'\x00' * 16 creates a bytes object of length 16 filled with zeros
    block = b'\x00' * 16
    
    # XOR the OTP blocks with the zero block to compute data parts
    # the XOR is done because the encryption is symmetric
    # this means that if you XOR the ciphertext with the same key, you get the plaintext
    # in this case, the key is the OTP
    data_part1 = xor(otp1, block)
    data_part2 = xor(otp2, block)
    data = data_part1 + data_part2  # Concatenate the two data parts
    
    # Send the computed data to the server
    # the function sendlineafter is used to send data to the server after waiting for a specific prompt
    conn.sendlineafter(b'Input: ', data.hex().encode())
    
    # Receive the ciphertext from the server
    output_line = conn.recvline().decode().strip()
    cipher_hex = output_line.split(': ')[1]  # Extract the ciphertext in hexadecimal format
    cipher = bytes.fromhex(cipher_hex)  # Convert the ciphertext from hex to bytes
    
    # Split the ciphertext into two 16-byte blocks

    cipher1, cipher2 = cipher[:16], cipher[16:]
    
    # Determine the encryption mode based on the ciphertext blocks
    # we recognize that if the two ciphertext blocks are equal, then the mode is ECB
    # otherwise, it is CBC
    mode = 'ECB' if cipher1 == cipher2 else 'CBC'
    
    # Send the guessed mode (ECB or CBC) to the server
    conn.sendlineafter(b'(ECB, CBC)\n', mode.encode())
    
    # Check the server's response to see if the guess was correct
    resp = conn.recvline().decode().strip()
    if 'OK' not in resp:
        print(f"Failed at challenge {_}")
        exit()

# Receive and print the flag after successfully completing all challenges
conn.recvuntil(b'The flag is: ')
flag = conn.recvline().decode().strip()
print(f"Flag: {flag}")

# Close the connection
conn.close()