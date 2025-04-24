#Needless to say, you need the proper authorization cookie to get the flag

#nc 130.192.5.212 6552

#FLAG: CRYPTO25{598ea8bb-28ba-42ba-9557-5cea53b7fdae}

from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes, bytes_to_long
from Crypto.Util.Padding import pad

import os
os.environ['PWNLIB_NOTERM'] = 'True'  # Configuration patch to allow pwntools to be run inside of an IDE
os.environ['PWNLIB_SILENT'] = 'True'

from pwn import *

HOST = "130.192.5.212"
PORT = 6552
BLOCK_SIZE = 16

def main():
    io = remote(HOST, PORT)

    username = b"A" * (BLOCK_SIZE - len("username=") ) + pad(b"true", AES.block_size) + b"A" * (BLOCK_SIZE - len("&admin="))
    io.sendlineafter("Username: ", username)

    cookie = long_to_bytes(int(io.recvline().strip()))
    
    forged_cookie_bytes = cookie[:16] + cookie[32:48] + cookie[16:32]
    forged_cookie = str(bytes_to_long(forged_cookie_bytes)).encode()

    print(f"\n[*] Forged cookie: {forged_cookie.hex()}")

    io.recvuntil(b'What do you want to do?\n')
    io.sendline(b'flag')
    io.recvuntil(b'Cookie: ')
    io.sendline(forged_cookie)

    flag = io.recv(1024)
    print(flag.decode())
    io.close()

if __name__ == "__main__":
    main()