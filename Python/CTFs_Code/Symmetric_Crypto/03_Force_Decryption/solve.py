#To get your flag, forge a payload that decrypts to a fixed value...

#nc 130.192.5.212 6523

#################################################################################
#FLAG: CRYPTO25{096496ba-c281-42d9-84f4-af05b39cb006}
#################################################################################

from pwn import *

HOST = "130.192.5.212"
PORT = 6523

def main():
    leak = b"mynamesuperadmin"
    pt = b"B" * 16  # Any 16-byte value != leak

    io = remote(HOST, PORT)

    # Encrypt step
    io.recvuntil(b'> ')
    io.sendline(b'enc')
    io.recvuntil(b'> ')
    io.sendline(pt.hex().encode())
    iv_line = io.recvline().decode()
    ct_line = io.recvline().decode()
    iv = bytes.fromhex(iv_line.split(": ")[1].strip())
    ct = bytes.fromhex(ct_line.split(": ")[1].strip())

    print(f"Plaintext: {pt}")
    print(f"IV: {iv.hex()}")
    print(f"Ciphertext: {ct.hex()}")

    # Correct forged IV: leak ^ pt ^ iv
    forged_iv = bytes([a ^ b ^ c for a, b, c in zip(leak, pt, iv)])
    print(f"Forged IV: {forged_iv.hex()}")

    # Decrypt step
    io.recvuntil(b'> ')
    io.sendline(b'dec')
    io.recvuntil(b'> ')
    io.sendline(ct.hex().encode())
    io.recvuntil(b'> ')
    io.sendline(forged_iv.hex().encode())
    print(io.recvall().decode())

if __name__ == "__main__":
    main()
