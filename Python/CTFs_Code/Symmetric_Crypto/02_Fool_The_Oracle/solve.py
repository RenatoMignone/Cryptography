#you have the code, guess the flag

#nc 130.192.5.212 6541

#################################################################################
#FLAG: CRYPTO25{96ce8a93-d548-4f88-bc6c-db6eb3c96382}
#################################################################################

from pwn import remote
import sys

HOST = "130.192.5.212"
PORT = 6541
BLOCK_SIZE = 16

def get_ciphertext(io, payload_hex):
    io.recvuntil(b'> ')
    io.sendline(b'enc')
    io.recvuntil(b'> ')
    io.sendline(payload_hex.encode())
    ct = io.recvline().strip().decode()
    return ct

def main():
    io = remote(HOST, PORT)
    flag_len = len("CRYPTO25{}") + 36
    recovered = b''

    for i in range(flag_len):
        pad_len = BLOCK_SIZE - (len(recovered) % BLOCK_SIZE) - 1
        prefix = b'A' * pad_len
        ct_hex = get_ciphertext(io, prefix.hex())
        ct_bytes = bytes.fromhex(ct_hex)
        block_idx = (len(prefix) + len(recovered)) // BLOCK_SIZE
        target_block = ct_bytes[block_idx*BLOCK_SIZE:(block_idx+1)*BLOCK_SIZE]

        found = False
        for b in range(256):
            guess = prefix + recovered + bytes([b])
            guess_hex = guess.hex()
            ct_guess_hex = get_ciphertext(io, guess_hex)
            ct_guess_bytes = bytes.fromhex(ct_guess_hex)
            guess_block = ct_guess_bytes[block_idx*BLOCK_SIZE:(block_idx+1)*BLOCK_SIZE]
            if guess_block == target_block:
                recovered += bytes([b])
                sys.stdout.write(chr(b))
                sys.stdout.flush()
                found = True
                break
        if not found:
            print("\n[!] Failed to recover next byte.")
            break
    print("\nRecovered flag:", recovered.decode(errors='replace'))

if __name__ == "__main__":
    main()
