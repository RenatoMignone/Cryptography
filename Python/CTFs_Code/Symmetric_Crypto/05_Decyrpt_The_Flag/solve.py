#As I don't have enough fantasy, I'm just reusing the same text as other challenges... 
#...read the challenge code and find the flag!

#nc 130.192.5.212 6561

#################################################################################
#FLAG: CRYPTO25{5a60b310-f194-4661-941b-eab7e18dc073}
#################################################################################

from pwn import *

HOST = "130.192.5.212"
PORT = 6561

def get_flag(seed):
    io = remote(HOST, PORT)
    io.recvuntil(b"> ")
    io.sendline(str(seed).encode())
    io.recvuntil(b"secret!\n")
    flag_ctxt_hex = io.recvline().strip().decode()
    flag_ctxt = bytes.fromhex(flag_ctxt_hex)
    io.recvuntil(b"(y/n)")
    io.sendline(b"y")
    io.recvuntil(b"message? ")
    known = b"A" * len(flag_ctxt)
    io.sendline(known)
    known_ctxt_hex = io.recvline().strip().decode()
    known_ctxt = bytes.fromhex(known_ctxt_hex)
    io.close()
    flag = bytes(a ^ b ^ c for a, b, c in zip(flag_ctxt, known_ctxt, known))
    return flag

if __name__ == "__main__":
    # Try seed 0 (can brute-force if needed)
    flag = get_flag(0)
    print("Recovered flag:", flag.decode(errors="ignore"))
