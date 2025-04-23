"""
fool this new one...

nc 130.192.5.212 6542

FLAG: CRYPTO25{ad3c6c1e-5cac-4c87-b5c3-a5dab511fee3}

"""

"""
Exploit script for the ECB oracle with 5-byte random prefix.
Connects to remote service and recovers the flag via byte-at-a-time attack.
"""
from pwn import remote
import sys

HOST = "130.192.5.212"
PORT = 6542
BLOCK_SIZE = 16
# Known flag length: len("CRYPTO25{}") + 36 = 10 + 36 = 46
FLAG_LEN = 46


def get_ciphertext(io, payload_hex):
    """Send 'enc' command and payload hex, receive ciphertext hex."""
    io.recvuntil(b'> ')
    io.sendline(b'enc')
    io.recvuntil(b'> ')
    io.sendline(payload_hex.encode())
    return io.recvline().strip().decode()


def find_prefix_alignment(io):
    """
    Finds the number of padding bytes to align our input to block boundaries,
    and the block index where our controlled data begins.
    Returns (pad_len, start_block).
    """
    for pad in range(0, BLOCK_SIZE):
        test = b'A' * (pad + 2 * BLOCK_SIZE)
        ct_hex = get_ciphertext(io, test.hex())
        ct = bytes.fromhex(ct_hex)
        # Split into blocks
        blocks = [ct[i:i+BLOCK_SIZE] for i in range(0, len(ct), BLOCK_SIZE)]
        # Look for two identical consecutive blocks
        for i in range(len(blocks) - 1):
            if blocks[i] == blocks[i+1]:
                # Found alignment
                return pad, i
    raise Exception("Failed to find prefix alignment")


def main():
    io = remote(HOST, PORT)
    # 1) Find pad_len and the block index where our 'A' blocks start
    pad_len, start_block = find_prefix_alignment(io)
    print(f"[+] Alignment found: pad_len={pad_len}, start_block={start_block}")

    recovered = b''
    for idx in range(FLAG_LEN):
        # Number of bytes to pad so that the next unknown flag byte
        # will be at the end of a block
        pad_bytes = pad_len + (BLOCK_SIZE - 1 - (len(recovered) % BLOCK_SIZE))
        prefix = b'A' * pad_bytes
        # Obtain ciphertext block for real oracle
        ct_hex = get_ciphertext(io, prefix.hex())
        ct = bytes.fromhex(ct_hex)
        # Target block index shifts as we recover more bytes
        block_idx = start_block + (len(recovered) // BLOCK_SIZE)
        target_block = ct[block_idx*BLOCK_SIZE:(block_idx+1)*BLOCK_SIZE]

        # Brute-force next byte
        found = False
        for b in range(256):
            guess = prefix + recovered + bytes([b])
            ct_guess_hex = get_ciphertext(io, guess.hex())
            ct_guess = bytes.fromhex(ct_guess_hex)
            guess_block = ct_guess[block_idx*BLOCK_SIZE:(block_idx+1)*BLOCK_SIZE]
            if guess_block == target_block:
                recovered += bytes([b])
                sys.stdout.write(chr(b))
                sys.stdout.flush()
                found = True
                break
        if not found:
            print(f"\n[!] Failed to recover byte {idx}")
            break

    print(f"\n[+] Recovered flag: {recovered.decode()}")


if __name__ == "__main__":
    main()
