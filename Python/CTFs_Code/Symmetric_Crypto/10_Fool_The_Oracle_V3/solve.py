#...even more complex now...

#nc 130.192.5.212 6543

#################################################################################
#FLAG: CRYPTO25{e3ab2169-39d5-43aa-bde7-02286c2e2e56}
#################################################################################

# This script performs a byte-at-a-time ECB decryption attack with a random-length prefix.
# It first finds the prefix alignment, then recovers the flag one byte at a time by exploiting the ECB oracle.

from pwn import remote
import sys

HOST = "130.192.5.212"
PORT = 6543
# Block size for the cipher (likely AES)
BLOCK_SIZE = 16
# Known flag length: len("CRYPTO25{}") + 36 = 46
FLAG_LEN = 46  # len("CRYPTO25{}") + 36

def get_ciphertext(io, payload_hex):

    io.recvuntil(b'> ')
    io.sendline(b'enc')
    io.recvuntil(b'> ')
    io.sendline(payload_hex.encode())
    # Receive and decode ciphertext
    return io.recvline().strip().decode()

def find_prefix_alignment(io):
    """
    Find the number of bytes needed to align our input to a block boundary,
    and the block index where our controlled data starts.
    Returns (pad_len, start_block).
    """
    for pad in range(0, BLOCK_SIZE):
        # Prepare test input with increasing padding
        test = b'A' * (pad + 2 * BLOCK_SIZE)
        # Get ciphertext for test input
        ct_hex = get_ciphertext(io, test.hex())
        # Convert ciphertext from hex to bytes
        ct = bytes.fromhex(ct_hex)
        # Split into blocks
        blocks = [ct[i:i+BLOCK_SIZE] for i in range(0, len(ct), BLOCK_SIZE)]
        # Look for two identical consecutive blocks
        for i in range(len(blocks) - 1):
            if blocks[i] == blocks[i+1]:
                # Found alignment
                return pad, i
    # If alignment not found, raise exception
    raise Exception("Failed to find prefix alignment")

def main():
    # Connect to the remote server
    io = remote(HOST, PORT)
    # Find pad_len and the block index where our 'A' blocks start
    pad_len, start_block = find_prefix_alignment(io)
    # Print alignment information
    print(f"[+] Alignment found: pad_len={pad_len}, start_block={start_block}")

    # Buffer for recovered flag bytes
    recovered = b''
    for idx in range(FLAG_LEN):
        # Number of bytes to pad so that the next unknown flag byte
        # will be at the end of a block
        pad_bytes = pad_len + (BLOCK_SIZE - 1 - (len(recovered) % BLOCK_SIZE))
        # Prepare prefix for alignment
        prefix = b'A' * pad_bytes
        # Obtain ciphertext block for real oracle
        ct_hex = get_ciphertext(io, prefix.hex())
        # Convert ciphertext from hex to bytes
        ct = bytes.fromhex(ct_hex)
        # Target block index shifts as we recover more bytes
        block_idx = start_block + (len(recovered) // BLOCK_SIZE)
        # Extract target ciphertext block
        target_block = ct[block_idx*BLOCK_SIZE:(block_idx+1)*BLOCK_SIZE]

        # Flag to indicate if the correct byte was found
        found = False
        for b in range(256):
            # Construct guess input
            guess = prefix + recovered + bytes([b])
            # Get ciphertext for guess input
            ct_guess_hex = get_ciphertext(io, guess.hex())
            # Convert guess ciphertext from hex to bytes
            ct_guess = bytes.fromhex(ct_guess_hex)
            # Extract guess block
            guess_block = ct_guess[block_idx*BLOCK_SIZE:(block_idx+1)*BLOCK_SIZE]
            # If blocks match, correct byte found
            if guess_block == target_block:
                # Append recovered byte
                recovered += bytes([b])
                # Print recovered character
                sys.stdout.write(chr(b))
                sys.stdout.flush()
                found = True
                break
        # If no byte found, print error and stop
        if not found:
            print(f"\n[!] Failed to recover byte {idx}")
            break

    # Print the recovered flag
    print(f"\n[+] Recovered flag: {recovered.decode(errors='replace')}")

if __name__ == "__main__":
    main()
