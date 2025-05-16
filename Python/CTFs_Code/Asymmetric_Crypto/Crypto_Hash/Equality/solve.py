#FLAG: CRYPTO25{4dc2e2e9-a14f-4382-8a44-f57852a626ef}

#!/usr/bin/env python3
from pwn import remote

HOST = "130.192.5.212"
PORT = 6631

# Two different 64-byte blocks whose MD4 digests collide but whose MD5 digests differ
s1_hex = ("839c7a4d7a92cb5678a5d5b9eea5a757"
          "3c8a74deb366c3dc20a083b69f5d2a3bb"
          "3719dc69891e9f95e809fd7e8b23ba631"
          "8edd45e51fe39708bf9427e9c3e8b9")
s2_hex = ("839c7a4d7a92cbd678a5d529eea5a757"
          "3c8a74deb366c3dc20a083b69f5d2a3bb"
          "3719dc69891e9f95e809fd7e8b23ba631"
          "8edc45e51fe39708bf9427e9c3e8b9")

# Confirm MD4(s1) == MD4(s2) but MD5(s1) != MD5(s2)
# (this collision pair comes from Asecuritysite’s MD4‐collision examples) :contentReference[oaicite:0]{index=0}

def main():
    conn = remote(HOST, PORT)
    conn.recvuntil(b"Enter the first string: ")
    conn.sendline(s1_hex.encode())
    conn.recvuntil(b"Enter your second string: ")
    conn.sendline(s2_hex.encode())
    print(conn.recvall().decode())

if __name__ == "__main__":
    main()
