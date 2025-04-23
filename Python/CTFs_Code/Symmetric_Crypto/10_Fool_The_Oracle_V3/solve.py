#...even more complex now...

#nc 130.192.5.212 6543

#################################################################################
#FLAG: CRYPTO25{e3ab2169-39d5-43aa-bde7-02286c2e2e56}
#################################################################################

from pwn import remote
import sys

HOST = "130.192.5.212"
PORT = 6543
BLOCK_SIZE = 16
FLAG_LEN = 46  # len("CRYPTO25{}") + 36

def get_ciphertext(io, payload_hex):
    io.recvuntil(b'> ')
    io.sendline(b'enc')
    io.recvuntil(b'> ')
    io.sendline(payload_hex.encode())
    return io.recvline().strip().decode()

def find_prefix_alignment(io):
    """
    Find the number of bytes needed to align our input to a block boundary,
    and the block index where our controlled data starts.
    Returns (pad_len, start_block).
    """
    for pad in range(0, BLOCK_SIZE):
        test = b'A' * (pad + 2 * BLOCK_SIZE)
        ct_hex = get_ciphertext(io, test.hex())
        ct = bytes.fromhex(ct_hex)
        blocks = [ct[i:i+BLOCK_SIZE] for i in range(0, len(ct), BLOCK_SIZE)]
        for i in range(len(blocks) - 1):
            if blocks[i] == blocks[i+1]:
                return pad, i
    raise Exception("Failed to find prefix alignment")

def main():
    io = remote(HOST, PORT)
    pad_len, start_block = find_prefix_alignment(io)
    print(f"[+] Alignment found: pad_len={pad_len}, start_block={start_block}")

    recovered = b''
    for idx in range(FLAG_LEN):
        pad_bytes = pad_len + (BLOCK_SIZE - 1 - (len(recovered) % BLOCK_SIZE))
        prefix = b'A' * pad_bytes
        ct_hex = get_ciphertext(io, prefix.hex())
        ct = bytes.fromhex(ct_hex)
        block_idx = start_block + (len(recovered) // BLOCK_SIZE)
        target_block = ct[block_idx*BLOCK_SIZE:(block_idx+1)*BLOCK_SIZE]

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

    print(f"\n[+] Recovered flag: {recovered.decode(errors='replace')}")

if __name__ == "__main__":
    main()
