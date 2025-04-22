#!/usr/bin/env python3
from pwn import remote
from Crypto.Util.number import bytes_to_long, long_to_bytes

HOST = "130.192.5.212"
PORT = 6552
BLOCK = 16

def leak_blocks(username: bytes):
    """
    Open a fresh connection, send `username` at the "Username:" prompt,
    receive back the ECB‐encrypted cookie as a big integer, split it
    into 16‐byte blocks, then close.
    """
    r = remote(HOST, PORT)
    r.recvuntil(b"Username: ")
    r.sendline(username)
    data = r.recvline().strip()
    ct = long_to_bytes(int(data))
    blocks = [ ct[i:i+BLOCK] for i in range(0, len(ct), BLOCK) ]
    r.close()
    return blocks

def send_forged_cookie(forged_int: int):
    """
    Open a fresh connection, eat the login, then from the menu
    request the flag using our forged cookie.
    """
    r = remote(HOST, PORT)
    # eat the login prompt
    r.recvuntil(b"Username: ")
    r.sendline(b"whatever")
    r.recvline()            # the server prints us a ciphertext we ignore
    r.recvuntil(b"> ")      # now we are at the menu
    r.sendline(b"flag")     # choose the flag command
    r.recvuntil(b"Cookie: ")
    r.sendline(str(forged_int).encode())
    # this line should print: "OK! Your flag: ... "
    print(r.recvline().decode().strip())
    r.close()

def main():
    # —————————————————————————————————————————————————————
    # 1) Leak C1, C2 by making "username="+A*16+"&admin=" exactly 2 blocks
    u1 = b"A"*16
    B1 = leak_blocks(u1)
    C1, C2 = B1[0], B1[1]

    # —————————————————————————————————————————————————————
    # 2) Leak the block that encrypts "true"+12×\x0c as a single block
    #    by choosing a 15‐byte username ending in "true"
    u2 = b"B"*11 + b"true"
    B2 = leak_blocks(u2)
    # With len(u2)=15 we get exactly 3 blocks, and block 2 is "true"+padding
    C_true = B2[2]

    # —————————————————————————————————————————————————————
    # 3) Splice them together & send to get the flag
    forged = C1 + C2 + C_true
    forged_int = bytes_to_long(forged)
    send_forged_cookie(forged_int)

if __name__ == "__main__":
    main()
