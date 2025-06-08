#################################################################################
#As I don't have enough fantasy, I'm just reusing the same text as other challenges... 
#...read the challenge code and find the flag!

#nc 130.192.5.212 6561

#################################################################################
#FLAG: CRYPTO25{5a60b310-f194-4661-941b-eab7e18dc073}
#################################################################################

#################################################################################
#Attack: Key Stream Reuse
#################################################################################

from pwn import *

HOST = "130.192.5.212"
PORT = 6561

def get_flag():

    io = remote(HOST, PORT)
    io.recvuntil(b"> ")

    # The .encode() method converts the seed to bytes
    io.sendline(str(0).encode())

    # Wait for the ciphertext of the flag
    io.recvuntil(b"secret!\n")

    # Read the flag ciphertext in hex
    flag_ctxt_hex = io.recvline().strip().decode()

    # Convert flag ciphertext from hex to bytes
    flag_ctxt = bytes.fromhex(flag_ctxt_hex)

    io.recvuntil(b"(y/n)")
    io.sendline(b"y")

    io.recvuntil(b"message? ")
    
    # Prepare known plaintext of same length as flag ciphertext
    known = b"A" * len(flag_ctxt)

    # Send known plaintext
    io.sendline(known)

    # Read ciphertext of known plaintext in hex
    known_ctxt_hex = io.recvline().strip().decode()
    
    # Convert known ciphertext from hex to bytes
    known_ctxt = bytes.fromhex(known_ctxt_hex)
    io.close()

    # Doing the XOR operation between the known ciphertext and the known plaintext i get the stream
    keystream = bytes(a ^ b for a, b in zip(known_ctxt, known))

    # Now I can XOR the flag ciphertext with the keystream to recover the flag
    flag = bytes(a ^ b for a, b in zip(flag_ctxt, keystream))

    return flag

if __name__ == "__main__":
    flag = get_flag()

    print("Recovered flag:", flag.decode(errors="ignore"))
