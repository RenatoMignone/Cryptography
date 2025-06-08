# You have the code, access the server and get the flag!

# nc 130.192.5.212 6645

# Looking at the code, this implements an RSA blinding attack, 
# which falls under the category of implementation attacks.

#FLAG: CRYPTO25{af37efa5-de5b-4de2-adcd-43324caca805}

# ─── Attack ──────────────────────────────────────────────────────────────────────
# Attack Type: Implementation Attacks
# This is classified as an implementation attack because it exploits
# the improper implementation of the RSA service that allows both
# encryption and decryption operations without proper access controls.
# Using RSA blinding, we can trick the server into decrypting our target
# ciphertext by disguising it as a different value.

# ─── Steps ──────────────────────────────────────────────────────────────────────
#   1. Connect to the server and read the modulus n and target ciphertext c.
#   2. Choose a blinding factor s and compute the blinded ciphertext c' = c · s^e mod n.
#   3. Request decryption of c' to obtain the blinded plaintext m' = m · s mod n.
#   4. Unblind by computing m = m' · s^(-1) mod n to recover the original message.
#   5. Convert the recovered message to bytes to reveal the flag.

# ─── Server Information ─────────────────────────────────────────────────────────
# nc 130.192.5.212 6645

from pwn import remote
from Crypto.Util.number import inverse, long_to_bytes

# ─── Given Values ────────────────────────────────────────────────────────────────
HOST = '130.192.5.212'
PORT = 6645
e = 65537

def main():
    # ─── Step 1: Connect and read n and target ciphertext ──────────────────────
    conn = remote(HOST, PORT)
    n = int(conn.recvline().strip())
    c = int(conn.recvline().strip())

    # ─── Step 2: Choose blinding factor and compute blinded ciphertext ─────────
    s = 2  # blinding factor (any value != 1 mod n works)

    # Now we compute the blinded ciphertext, which is c' = c * s^e mod n
    # "Blinded" means we multiply the ciphertext by a random value raised to the public exponent
    c_blinded = (c * pow(s, e, n)) % n

    # ─── Step 3: Request decryption of blinded ciphertext ──────────────────────
    conn.sendline(b'd' + str(c_blinded).encode())
    m_blinded = int(conn.recvline().strip())

    # ─── Step 4: Unblind to recover original message ───────────────────────────
    # This inverse operation does m = m_blinded * s^(-1) mod n
    m = (m_blinded * inverse(s, n)) % n

    # ─── Step 5: Convert to bytes and print flag ───────────────────────────────
    flag = long_to_bytes(m)
    print(flag.decode())

if __name__ == '__main__':
    main()
