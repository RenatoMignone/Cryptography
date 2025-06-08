#################################################################################
#Read the code. If you really understood it, you can correctly guess the mode. 
#If you do it with a probability higher than 2^128 you'll get the flag.

#nc 130.192.5.212 6531

#################################################################################
# FLAG: CRYPTO25{3709585c-5eda-4f6a-b1e5-a93e0cf99f93}
#################################################################################

#################################################################################
#Attack: ECB vs CBC Understading
#################################################################################


from pwn import *


#----------------------------------------------------------------------------
# XOR function to compute the XOR of two byte sequences
def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


#----------------------------------------------------------------------------
conn = remote('130.192.5.212', 6531)

# Loop through 128 challenges because the challenge is designed to run 128 times
for i in range(128):

    conn.recvuntil(f'Challenge #{i}\n'.encode())
    
    # We transform the hex value of the OTP into bytes
    otp = bytes.fromhex(conn.recvline().decode().split(': ')[1])
    
    # this because the OTP is 32 bytes long, so we divide it because the AES block size is 16 bytes
    # Create two 16-byte blocs of zeros
    data = xor(otp, b'\x00' * 32)
    
    # Send the crafted data to the server
    conn.sendlineafter(b'Input: ', data.hex().encode())
    
    # Receive the ciphertext from the server
    cipher = bytes.fromhex(conn.recvline().decode().split(': ')[1])
    
    # Determine the encryption mode based on the ciphertext blocks
    # we recognize that if the two ciphertext blocks are equal, then the mode is ECB
    mode = 'ECB' if cipher[:16] == cipher[16:] else 'CBC'
    
    # Send the guessed mode (ECB or CBC) to the server
    conn.sendlineafter(b'(ECB, CBC)\n', mode.encode())
    
    # Check the server's response to see if the guess was correct
    if b'OK' not in conn.recvline():
        print(f"Failed at challenge {i}")
        exit()

# Receive and print the flag after successfully completing all challenges
conn.recvuntil(b'The flag is: ')
print('Flag:', conn.recvline().decode().strip())

# Close the connection
conn.close()