# You have the code, access the server and get the flag!

# nc 130.192.5.212 6645

#FLAG: CRYPTO25{af37efa5-de5b-4de2-adcd-43324caca805}

#!/usr/bin/env python3
from pwn import remote
from Crypto.Util.number import inverse, long_to_bytes

HOST = '130.192.5.212'
PORT = 6645

e = 65537

def main():
    # 1) connect and read n and the challenge ciphertext c
    conn = remote(HOST, PORT)
    n = int(conn.recvline().strip())
    c = int(conn.recvline().strip())

    # 2) pick any blinding factor s != 1 mod n
    #    (we choose 2 here for simplicity)
    s = 2

    # 3) compute blinded ciphertext c' = c * s^e mod n
    c_blinded = (c * pow(s, e, n)) % n

    # 4) ask the server to decrypt c'
    #    prefix 'd' to indicate decryption request
    conn.sendline(b'd' + str(c_blinded).encode())
    m_blinded = int(conn.recvline().strip())

    # 5) unblind: m = m_blinded * inverse(s) mod n
    m = (m_blinded * inverse(s, n)) % n

    # 6) convert to bytes and print the flag
    flag = long_to_bytes(m)
    print(flag.decode())

if __name__ == '__main__':
    main()
