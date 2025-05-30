#To get your flag, forge a payload that decrypts to a fixed value...

#nc 130.192.5.212 6523

#################################################################################
#FLAG: CRYPTO25{096496ba-c281-42d9-84f4-af05b39cb006}
#################################################################################

#################################################################################
# Attack: Bit Flipping Attack CBC.
#################################################################################

#################################################################################
# Attack Description: The attacker forges the IV to force the decrypted 
# plaintext to a chosen value and obtain the flag, (CBC IV manipulation).
#################################################################################

from pwn import *

HOST = "130.192.5.212"
PORT = 6523

def main():

    # The fixed value get from the server
    leak = b"mynamesuperadmin" 

    # Any 16-byte value not equal to leak, used as plaintext
    plaintext = b"B" * 16

    io = remote(HOST, PORT)

    # Encrypt step
    io.recvuntil(b'> ')
    io.sendline(b'enc')

    # Send plaintext in hex encoding
    io.recvuntil(b'> ')
    io.sendline(plaintext.hex().encode())

    # Read the IV and ciphertext from the response
    iv_line = io.recvline().decode()
    ct_line = io.recvline().decode()

    # Parse IV from response
    iv = bytes.fromhex(iv_line.split(": ")[1].strip())
    # Parse ciphertext from response
    ct = bytes.fromhex(ct_line.split(": ")[1].strip())

    # This XOR is done in order to forge the IV so that the decryption process done in the server side, returns a value equal to the leak.
    # When doing the XOR between the plaintext and the IV you get back a value that when XORed again with the leak, will
    # Give you the right initialization vector.

    keystream = bytes([a ^ b for a, b in zip(leak, plaintext)])
    
    forged_iv = bytes([a ^ b for a, b in zip(iv, keystream)])

    print(f"Forged IV: {forged_iv.hex()}")

    # Decrypt step
    io.recvuntil(b'> ')
    io.sendline(b'dec')

    io.recvuntil(b'> ')
    io.sendline(ct.hex().encode())

    io.recvuntil(b'> ')
    # Send forged IV in hex encoding
    io.sendline(forged_iv.hex().encode())


    print(io.recvall().decode())

if __name__ == "__main__":
    main()
