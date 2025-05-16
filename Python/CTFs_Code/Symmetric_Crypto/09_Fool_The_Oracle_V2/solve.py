#################################################################################
#fool this new one...

#nc 130.192.5.212 6542

#################################################################################
#FLAG: CRYPTO25{ad3c6c1e-5cac-4c87-b5c3-a5dab511fee3}
#################################################################################

#################################################################################
# Attack: Adaptive Chosen Plaintext Attack
#################################################################################

#################################################################################
# Attack Description: The attacker aligns their input after the random prefix 
# and recovers the flag one byte at a time using the ECB oracle.
#################################################################################

# This script performs a byte-at-a-time ECB decryption attack with a random-length prefix.
# It first finds the prefix alignment, then recovers the flag one byte at a time by exploiting the ECB oracle.


#FLAG: CRYPTO25{ad3c6c1e-5cac-4c87-b5c3-a5dab511fee3}

# Attack: Adaptive Chosen Plaintext Attack

# Attack Description: The attacker aligns their input after the random prefix 
# and recovers the flag one byte at a time using the ECB oracle.

# This script performs a byte-at-a-time ECB decryption attack with a random-length prefix.
# It first finds the prefix alignment, then recovers the flag one byte at a time by exploiting the ECB oracle.

from pwn import *
from Crypto.Util.Padding import pad
import binascii

BLOCK_SIZE = 16
HOST = "130.192.5.212" 
PORT = 6542

def get_ciphertext(io, user_input: bytes) -> bytes:
    io.sendlineafter(b"> ", b"enc") # Send the "enc" command
    io.sendlineafter(b"> ", user_input.hex().encode()) 
    line = io.recvline().strip()
    return bytes.fromhex(line.decode())

def find_alignment(io) -> int:
    """Finds the number of prefix padding bytes needed to align our input to a block boundary."""
    for pad_len in range(BLOCK_SIZE * 2):
        payload = b"A" * pad_len + b"B" * (BLOCK_SIZE * 2) # create a payload with padding up to 2 blocks 
        ct = get_ciphertext(io, payload)

        # Search for two identical adjacent blocks 
        #In ECB mode, if two plaintext blocks are identical, their ciphertext blocks will also be identical.
        #If your two B-filled blocks are aligned with the block boundaries (i.e., not split by the random prefix), their ciphertexts will be the same.
        #If they are not aligned, the random prefix will cause the blocks to be different, so their ciphertexts will not match.

        for i in range(0, len(ct) - BLOCK_SIZE * 2, BLOCK_SIZE): 
            if ct[i:i+BLOCK_SIZE] == ct[i+BLOCK_SIZE:i+2*BLOCK_SIZE]:
                print(f"[+] Alignment found! Need {pad_len} padding bytes.")
                return pad_len
    raise Exception("[-] Failed to find alignment")


def recover_flag():
    io = remote(HOST, PORT)
    prefix_pad_len = find_alignment(io) #guess the prefix padding length

    known = b""
    total_flag_len = len("CRYPTO25{}") + 36  #from challenge code
    print(f"[*] Starting ECB attack. Target length: {total_flag_len} bytes")

    while len(known) < total_flag_len:

        # The pad_len value is used to have the byte of interest at the end of the block
        # This because we are using ECB mode, and we want to guess the last byte of the block
        pad_len = (BLOCK_SIZE - (len(known) % BLOCK_SIZE) - 1) % BLOCK_SIZE # calculate padding length
        prefix = b"A" * (prefix_pad_len + pad_len) # based on alignment, we know how many bytes to pad

        # This is a value that does not changes in the loop
        start_index = (prefix_pad_len + 5) // BLOCK_SIZE  # +5 for the random prefix
        #This one is the currect block we are analyzing
        block_index = start_index + (len(known) // BLOCK_SIZE) # calculate the block index of the byte we want to guess

        target = get_ciphertext(io, prefix) #send the prefix to the oracle and get the ciphertext

        # The value "block_index * BLOCK_SIZE" is the start of the block we are analyzing
        # In the test_cipher variable, we got from the server the ciphertext of the prefix + known + b
        # THe slice goes until the next block after the one we are analyzing
        target_block = target[block_index * BLOCK_SIZE:(block_index + 1) * BLOCK_SIZE]

        # The value 256 is the maximum value of a byte
        for b in range(256):

            test_input = prefix + known + bytes([b])
            test_cipher = get_ciphertext(io, test_input)

            test_block = test_cipher[block_index * BLOCK_SIZE : (block_index + 1) * BLOCK_SIZE]

            if test_block == target_block:
                known += bytes([b])
                print(f"[+] Found byte: {bytes([b])} | Current flag: {known.decode(errors='ignore')}")
                break
        else:
            print("[-] Failed to match next byte.")
            break

    print(f"[✔] Final flag: {known.decode(errors='ignore')}")
    io.close()

if _name_ == "_main_":
    recover_flag()