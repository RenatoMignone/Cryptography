#FLAG: CRYPTO25{b4b6d1f1-929c-4a41-9900-51091ea9b258}

#!/usr/bin/env python3
from pwn import remote
from fractions import Fraction
from Crypto.Util.number import long_to_bytes

HOST = '130.192.5.212'
PORT = 6647

def get_parity(r, c):
    """Send the ciphertext c to the oracle and return 0 or 1."""
    r.sendline(str(c).encode())
    return int(r.recvline().strip())

def main():
    # 1) connect and read n and the ciphertext c
    r = remote(HOST, PORT)
    n = int(r.recvline().strip())
    c = int(r.recvline().strip())

    # 2) precompute factor = 2^e mod n
    e = 65537
    two_e = pow(2, e, n)

    # 3) set up our search interval [low, high] as rationals
    low = Fraction(0)
    high = Fraction(n)

    # 4) for each bit of the 512-bit message:
    for i in range(n.bit_length()):
        # blind ciphertext by multiplying by (2^e)^i
        c = (c * two_e) % n

        # query the oracle for the LSB of the decrypted value
        bit = get_parity(r, c)

        # refine interval
        mid = (low + high) / 2
        if bit == 0:
            # plaintext * 2^i < n/2  → it’s in the lower half
            high = mid
        else:
            # plaintext * 2^i ≥ n/2 → it’s in the upper half
            low = mid

        # optional: print progress
        print(f"Recovered bit {i+1}/{n.bit_length()}: {bit}", end='\r')

    # 5) after all bits, low ≈ high ≈ m
    m = int(high)  # or int(low), they converge

    # 6) convert to bytes and print
    flag = long_to_bytes(m)
    print("\n\nRecovered flag:", flag.decode())

if __name__ == '__main__':
    main()
