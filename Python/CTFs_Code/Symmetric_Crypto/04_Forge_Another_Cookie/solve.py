#################################################################################
#Needless to say, you need the proper authorization cookie to get the flag

#nc 130.192.5.212 6552
#################################################################################
#FLAG: CRYPTO25{598ea8bb-28ba-42ba-9557-5cea53b7fdae}
#################################################################################

#################################################################################
#Attack: Copy and Paste Attack ECB.
#################################################################################

#################################################################################
# Attack Description: The attacker forges an admin cookie by rearranging 
# ciphertext blocks due to ECB's lack of diffusion between blocks. This is done
# in one single connection otherwise the server would change the key value.
#################################################################################

from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes, bytes_to_long
from Crypto.Util.Padding import pad

import os
# Patch pwntools to work in IDEs
os.environ['PWNLIB_NOTERM'] = 'True'  # Configuration patch to allow pwntools to be run inside of an IDE
os.environ['PWNLIB_SILENT'] = 'True'

from pwn import *

HOST = "130.192.5.212"
PORT = 6552
BLOCK_SIZE = 16

def main():
    # Connect to the remote challenge server
    io = remote(HOST, PORT)

    # Craft a username so that 'true' is aligned at the start of a block after 'admin='
    username = b"A" * (BLOCK_SIZE - len("username=") ) + pad(b"true", AES.block_size) + b"A" * (BLOCK_SIZE - len("&admin="))
    # Send the crafted username to the server
    io.sendlineafter("Username: ", username)

    # Receive the encrypted cookie from the server and convert it to bytes
    cookie = long_to_bytes(int(io.recvline().strip()))
    
    # Rearrange the ciphertext blocks to forge a cookie with admin=true
    forged_cookie_bytes = cookie[:16] + cookie[32:48] + cookie[16:32]
    # Convert the forged cookie bytes to a long integer string as expected by the server
    forged_cookie = str(bytes_to_long(forged_cookie_bytes)).encode()

    # Print the forged cookie (for debugging)
    print(f"\n[*] Forged cookie: {forged_cookie.hex()}")

    # Wait for the menu prompt
    io.recvuntil(b'What do you want to do?\n')
    # Send the 'flag' command to request the flag
    io.sendline(b'flag')
    # Wait for the cookie prompt
    io.recvuntil(b'Cookie: ')
    # Send the forged admin cookie
    io.sendline(forged_cookie)

    # Receive and print the flag from the server
    flag = io.recv(1024)
    print(flag.decode())
    # Close the connection
    io.close()

if __name__ == "__main__":
    main()