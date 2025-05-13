#################################################################################
#As I don't have enough fantasy, I'm just reusing the same text as other challenges... 
#...read the challenge code and find the flag!

#nc 130.192.5.212 6561

#################################################################################
#FLAG: CRYPTO25{5a60b310-f194-4661-941b-eab7e18dc073}
#################################################################################

#################################################################################
#Attack: Key Stream Reuse, The attacker exploits the reuse of the nonce and key in a stream cipher to recover the flag.
#################################################################################

#################################################################################
# Attack Description: The attacker exploits the reuse of the nonce and key in 
# a stream cipher to recover the flag.
#################################################################################


# This script performs a known-plaintext attack (specifically, a chosen-plaintext attack)
# against a stream cipher or OTP-like encryption. By submitting a known plaintext of the
# same length as the flag ciphertext, we can XOR the results to recover the flag.

from pwn import *

HOST = "130.192.5.212"
PORT = 6561

def get_flag(seed):

    io = remote(HOST, PORT)
    io.recvuntil(b"> ")
    # Send the seed as bytes
    io.sendline(str(seed).encode())

    # Wait for the ciphertext of the flag
    io.recvuntil(b"secret!\n")
    # Read the flag ciphertext in hex
    flag_ctxt_hex = io.recvline().strip().decode()
    # Convert flag ciphertext from hex to bytes
    flag_ctxt = bytes.fromhex(flag_ctxt_hex)

    io.recvuntil(b"(y/n)")
    # Send 'y' to encrypt a known message
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

    # Recover the flag using XOR: flag = flag_ctxt ^ known_ctxt ^ known
    flag = bytes(a ^ b ^ c for a, b, c in zip(flag_ctxt, known_ctxt, known))
    return flag

if __name__ == "__main__":
    # Try seed 0 (can brute-force if needed)
    flag = get_flag(0)
    # Print the recovered flag
    print("Recovered flag:", flag.decode(errors="ignore"))
