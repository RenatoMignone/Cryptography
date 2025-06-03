#FLAG: CRYPTO25{d153d414-d83d-45f2-9f90-f6628c479331}

from pwn import *
from base64 import b64decode, b64encode
import json

context.log_level = 'info'

HOST = '130.192.5.212'
PORT = 6551

BLOCK_SIZE = 16

def get_token(name, r):
    r.sendlineafter(b'name!\n> ', name)
    r.recvuntil(b'token: ')
    token = r.recvline().strip().decode()
    return b64decode(token)


def get_flag(forged_token, r):
    r.recvuntil(b'> ')  # menu
    r.sendline(b'flag')
    r.sendlineafter(b'token?\n> ', b64encode(forged_token))
    result = r.recvall()
    return result


def main():
    r = remote(HOST, PORT)

    name1 = b'ab' +b' ' *15 +  b'"surname' + b' '*8 + b' '*15 + b'":' + b' '*14 + b'true,' +b' '*11 +b'1234'

    #stampa name1 
    log.info("Crafted name: " + name1.decode())
    
    # stampa il plaintext token completo: {"username": name1, "admin": False} ma ogni 16 byte vai a capo
    # Serializza il JSON come stringa
    json_str = json.dumps({
        "username": name1.decode(),
        "admin": False
    })

    for i in range(0, len(json_str), 16):
        print(json_str[i:i+16])

    token1 = get_token(name1, r)  # 6 chars
    blocks1 = [token1[i:i+BLOCK_SIZE] for i in range(0, len(token1), BLOCK_SIZE)]

    # Debug print blocks (optional)
    log.info("Token1 blocks:")
    for i, b in enumerate(blocks1):
        log.info(f"Block {i}: {b.hex()}")

    # Step 3: Forge new token 
    forged = blocks1[0] + blocks1[6] + blocks1[5] + blocks1[2] + blocks1[4] + blocks1[7]
    log.success("Forged token (Base64): " + b64encode(forged).decode())

    # Step 4: Use forged token to get the flag
    response = get_flag(forged, r)
    print(response.decode())

if __name__ == "__main__":
    main()