# FLAG: CRYPTO25{b4b6d1f1-929c-4a41-9900-51091ea9b258}

# ─── Attack ──────────────────────────────────────────────────────────────────────
# Attack Type: LSB Oracle
# This is classified as an implementation attack because it exploits
# an oracle that reveals the least significant bit of decrypted ciphertexts.
# By repeatedly doubling the plaintext and querying the oracle, we can
# perform a binary search to recover the entire message bit by bit.

# ─── Steps ──────────────────────────────────────────────────────────────────────
#   1. Connect to the server and read the modulus n and ciphertext c.
#   2. Precompute 2^e mod n for blinding successive queries.
#   3. For each bit, multiply ciphertext by 2^e and query the LSB oracle.
#   4. Use binary search interval refinement based on the returned bit.
#   5. After all bits, convert the recovered plaintext to bytes.

# ─── Server Information ─────────────────────────────────────────────────────────
# nc 130.192.5.212 6647

#!/usr/bin/env python3
from pwn import remote
from fractions import Fraction
from Crypto.Util.number import long_to_bytes

# ─── Given Values ────────────────────────────────────────────────────────────────
HOST = '130.192.5.212'
PORT = 6647

def get_parity(r, c):
    """Send the ciphertext c to the oracle and return 0 or 1."""
    r.sendline(str(c).encode())
    return int(r.recvline().strip())

def main():
    # ─── Step 1: Connect and read n and ciphertext ─────────────────────────────
    r = remote(HOST, PORT)
    n = int(r.recvline().strip())
    c = int(r.recvline().strip())

    # ─── Step 2: Precompute blinding factor ────────────────────────────────────
    e = 65537
    two_e = pow(2, e, n)

    # ─── Step 3: Initialize binary search interval ─────────────────────────────
    low = Fraction(0)
    high = Fraction(n)

    # ─── Step 4: Binary search using LSB oracle ────────────────────────────────
    for i in range(n.bit_length()):
        # Blind ciphertext by multiplying by (2^e)^i
        c = (c * two_e) % n

        # Query the oracle for the LSB
        bit = get_parity(r, c)

        # Refine interval based on returned bit
        mid = (low + high) / 2
        if bit == 0:
            high = mid  # plaintext * 2^i < n/2 → lower half
        else:
            low = mid   # plaintext * 2^i ≥ n/2 → upper half

        print(f"Recovered bit {i+1}/{n.bit_length()}: {bit}", end='\r')

    # ─── Step 5: Convert recovered plaintext to bytes ──────────────────────────
    m = int(high)  # low and high converge to the plaintext
    flag = long_to_bytes(m)
    print("\n\nRecovered flag:", flag.decode())

if __name__ == '__main__':
    main()
