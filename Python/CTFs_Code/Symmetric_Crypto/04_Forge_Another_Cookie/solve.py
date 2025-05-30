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


from pwn import *

HOST = "130.192.5.212"
PORT = 6552
BLOCK_SIZE = 16

def main():

    io = remote(HOST, PORT)

    # Craft a new username composed of:
    # - A padding of 'A's to fill the block size minus the length of "username="
    # - The string "true" padded to the block size, in order to have it at the beginning of the second block
    # - A padding of 'A's to fill the block size minus the length of "&admin="
    username = (b"A" * (BLOCK_SIZE - len("username=") )) + (pad(b"true", AES.block_size)) + (b"A" * (BLOCK_SIZE - len("&admin=")))

    io.sendlineafter("Username: ", username)

    # Receive the encrypted cookie from the server and convert it to bytes
    cookie = long_to_bytes(int(io.recvline().strip()))
    
    # Rearrange the ciphertext blocks to forge a cookie with admin=true
    forged_cookie_bytes = cookie[:16] + cookie[32:48] + cookie[16:32]

    # Convert the forged cookie bytes to a long integer string as expected by the server
    forged_cookie = str(bytes_to_long(forged_cookie_bytes)).encode()

    # Print the forged cookie (for debugging)
    print(f"\nForged cookie: {forged_cookie.hex()}")

    io.recvuntil(b'What do you want to do?\n')
    io.sendline(b'flag')

    io.recvuntil(b'Cookie: ')

    io.sendline(forged_cookie)

    flag = io.recvall()
    print(flag.decode())

    io.close()

if __name__ == "__main__":
    main()