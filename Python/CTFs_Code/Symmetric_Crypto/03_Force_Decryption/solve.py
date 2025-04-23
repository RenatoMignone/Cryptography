#To get your flag, forge a payload that decrypts to a fixed value...

#nc 130.192.5.212 6523

#################################################################################
#FLAG: CRYPTO25{096496ba-c281-42d9-84f4-af05b39cb006}
#################################################################################

'''

This script performs a padding oracle attack to decrypt a ciphertext by 
forcing the decryption to yield a known plaintext.

'''

from pwn import *

HOST = "130.192.5.212"
PORT = 6523

def main():
    # The fixed value to force decryption to (the "leak")
    leak = b"mynamesuperadmin"  # The known plaintext to force decryption to
    # Any 16-byte value not equal to leak, used as plaintext
    pt = b"B" * 16

    # Connect to the remote server
    io = remote(HOST, PORT)

    #######################################################
    # Encrypt step
    io.recvuntil(b'> ')
    # Send 'enc' command
    io.sendline(b'enc')

    io.recvuntil(b'> ')
    # Send plaintext in hex encoding
    io.sendline(pt.hex().encode())

    # Receive IV line and decode
    iv_line = io.recvline().decode()
    # Receive ciphertext line and decode
    ct_line = io.recvline().decode()

    # Parse IV from response
    iv = bytes.fromhex(iv_line.split(": ")[1].strip())
    # Parse ciphertext from response
    ct = bytes.fromhex(ct_line.split(": ")[1].strip())

    # Print plaintext
    print(f"Plaintext: {pt}")
    # Print IV in hex
    print(f"IV: {iv.hex()}")
    # Print ciphertext in hex
    print(f"Ciphertext: {ct.hex()}")

    # Correct forged IV: leak ^ pt ^ iv
    # Compute the forged IV so that decryption yields the leak
    forged_iv = bytes([a ^ b ^ c for a, b, c in zip(leak, pt, iv)])
    # Print forged IV in hex
    print(f"Forged IV: {forged_iv.hex()}")

    # Decrypt step
    io.recvuntil(b'> ')
    # Send 'dec' command
    io.sendline(b'dec')

    io.recvuntil(b'> ')
    # Send ciphertext in hex encoding
    io.sendline(ct.hex().encode())

    io.recvuntil(b'> ')
    # Send forged IV in hex encoding
    io.sendline(forged_iv.hex().encode())


    print(io.recvall().decode())

if __name__ == "__main__":
    main()
