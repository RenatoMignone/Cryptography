#################################################################################
#you have the code, guess the flag

#nc 130.192.5.212 6541

#################################################################################
#FLAG: CRYPTO25{96ce8a93-d548-4f88-bc6c-db6eb3c96382}
#################################################################################

#################################################################################
# Attack: Adaptive Chosen Plaintext Attack 
#################################################################################

#################################################################################
# Attack Description: The attacker adaptively chooses plaintexts based on previous responses.
# By exploiting the deterministic nature of ECB, the attacker can recover the 
# secret appended to their input.
#################################################################################

'''
This script performs a byte-by-byte ECB oracle attack to recover a secret flag from a remote server.

The attack exploits the Electronic Codebook (ECB) mode of encryption, which encrypts 
identical plaintext blocks into identical ciphertext blocks. 
By carefully crafting inputs and observing the resulting ciphertext, it is possible to 
deduce the plaintext one byte at a time.

'''

from pwn import remote
import sys

HOST = "130.192.5.212"
PORT = 6541
# Block size for the cipher (likely AES)
BLOCK_SIZE = 16


# This function sends a payload to the server and retrieves the ciphertext.
# The payload is sent in hex encoding, and the server responds with the ciphertext. 
# This means that we are using the server as an oracle to get the ciphertext for our crafted input.
def get_ciphertext(io, payload_hex):
    io.recvuntil(b'> ')
    # Send 'enc' command to server
    io.sendline(b'enc')

    io.recvuntil(b'> ')
    # Send payload in hex encoding
    io.sendline(payload_hex.encode())
    # Receive and decode ciphertext
    ct = io.recvline().strip().decode()
    return ct



def main():
    # This is a byte-by-byte ECB oracle attack (ECB byte-at-a-time decryption).
    # Connect to the remote server
    io = remote(HOST, PORT)
    # Calculate expected flag length
    # This value is known from the server code
    flag_len = len("CRYPTO25{}") + 36

    # Buffer for recovered flag bytes
    recovered = b''

    for i in range(flag_len):
        # Calculate padding to align next unknown byte
        # This means we need to pad the input to the block size minus one
        pad_len = BLOCK_SIZE - (len(recovered) % BLOCK_SIZE) - 1

        # Create prefix of 'A's for alignment
        # Based on the current length of the recovered bytes
        prefix = b'A' * pad_len

        # Get ciphertext for current prefix
        ct_hex = get_ciphertext(io, prefix.hex())

        # Convert ciphertext from hex to bytes
        ct_bytes = bytes.fromhex(ct_hex)

        # Determine which block contains the target byte
        # This means we need to find the block index based on the length of the prefix and the recovered bytes
        block_idx = (len(prefix) + len(recovered)) // BLOCK_SIZE

        # Extract target ciphertext block
        target_block = ct_bytes[block_idx*BLOCK_SIZE:(block_idx+1)*BLOCK_SIZE]

        # Flag to indicate if the correct byte was found
        # Initialized to False
        # This means we will iterate over all possible byte values (0-255)
        # to find the correct one
        # This is the byte we are trying to guess
        found = False
        for b in range(256):
            # Construct guess input
            guess = prefix + recovered + bytes([b])
            # Convert guess to hex
            guess_hex = guess.hex()
            # Get ciphertext for guess
            ct_guess_hex = get_ciphertext(io, guess_hex)
            # Convert guess ciphertext to bytes
            ct_guess_bytes = bytes.fromhex(ct_guess_hex)
            # Extract guess block
            guess_block = ct_guess_bytes[block_idx*BLOCK_SIZE:(block_idx+1)*BLOCK_SIZE]
            # If blocks match, correct byte found
            if guess_block == target_block:
                # Append recovered byte
                recovered += bytes([b])
                # Print recovered character
                sys.stdout.write(chr(b))
                sys.stdout.flush()
                found = True
                break
        # If no byte found, stop
        if not found:
            print("\n[!] Failed to recover next byte.")
            break
    # Print the recovered flag
    print("\nRecovered flag:", recovered.decode(errors='replace'))

if __name__ == "__main__":
    main()
