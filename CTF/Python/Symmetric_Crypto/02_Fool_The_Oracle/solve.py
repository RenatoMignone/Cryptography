#FLAG: CRYPTO25{96ce8a93-d548-4f88-bc6c-db6eb3c96382}

# Attack: Adaptive Chosen Plaintext Attack 
# Attack Description: The attacker adaptively chooses plaintexts based on previous responses.
# By exploiting the deterministic nature of ECB, the attacker can recover the 
# secret appended to their input.

from pwn import *
from Crypto.Util.Padding import pad


#-----------------------------------------------------------------------------
# Constants
BLOCK_SIZE = 16
HOST = "130.192.5.212"
PORT = 6541
FLAG_LEN = 46


#-----------------------------------------------------------------------------
def get_ciphertext(io, user_input: bytes):
    io.sendlineafter(b"> ", b"enc")
    io.sendlineafter(b"> ", user_input.hex().encode()) 
    line = io.recvline().strip()
    return bytes.fromhex(line.decode())

#-----------------------------------------------------------------------------
def recover_flag():
    io = remote(HOST, PORT)

    # Known flag
    known = b""

    # Until we have recovered the entire flag
    while len(known) < FLAG_LEN: 

        # Calculate the padding length to align the next byte to guess at the end of a block
        # This is because of how the adaptive chosen plaintext attack works
        pad_len = (BLOCK_SIZE - (len(known) % BLOCK_SIZE) - 1) % BLOCK_SIZE 

        #We send a prefix of A's to align the next flag byte at the end of a block
        prefix = b"A" * pad_len 

        #We calculate the block index of the next flag byte
        block_index = (len(prefix) + len(known)) // BLOCK_SIZE

        #We send all the As to the server and get the ciphertext
        target = get_ciphertext(io, prefix) 

        #We extract the target block we want to match
        target_block = target[block_index * BLOCK_SIZE:(block_index + 1) * BLOCK_SIZE]

        #We iterate over all possible bytes (0-255) to find the next byte of the flag
        for b in range(256):

            #We create the test input by appending the current byte to the known flag and prefix
            test_input = prefix + known + bytes([b])

            #We get the ciphertext for the test input
            test_cipher = get_ciphertext(io, test_input)

            #We extract the block we want to check
            test_block = test_cipher[block_index * BLOCK_SIZE:(block_index + 1) * BLOCK_SIZE]

            #If the test block matches the target block, we have found the next byte of the flag
            if test_block == target_block: 
                known += bytes([b])
                print(f"Current flag: {known.decode(errors='ignore')}")
                break
        else:
            print("Failed to match next byte.")
            break

    print(f"flag: {known.decode(errors='ignore')}")

if __name__ == "__main__":
    recover_flag()