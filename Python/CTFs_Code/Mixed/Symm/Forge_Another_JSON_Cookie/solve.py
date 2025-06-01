from pwn import *
from base64 import b64decode, b64encode

context.log_level = 'info'

HOST = '130.192.5.212'
PORT = 6551

BLOCK_SIZE = 16


def get_token(name):
    r = remote(HOST, PORT)
    r.sendlineafter(b'name!\n> ', name.encode())
    r.recvuntil(b'token: ')
    token = r.recvline().strip().decode()
    r.close()
    return b64decode(token)


def get_flag(forged_token):
    r = remote(HOST, PORT)
    r.sendlineafter(b'name!\n> ', b'a')  # dummy name
    r.recvuntil(b'> ')  # menu
    r.sendline(b'flag')
    r.sendlineafter(b'token?\n> ', b64encode(forged_token))
    result = r.recvall()
    r.close()
    return result


def main():
    # Step 1: Get a normal token for a short username
    token1 = get_token("aaaaaa")  # 6 chars
    blocks1 = [token1[i:i+BLOCK_SIZE] for i in range(0, len(token1), BLOCK_SIZE)]

    # Step 2: Get a token where "true}" lands at the beginning of a block
    token2 = get_token("aatrue")  # username includes 'true'
    blocks2 = [token2[i:i+BLOCK_SIZE] for i in range(0, len(token2), BLOCK_SIZE)]

    # Debug print blocks (optional)
    log.info("Token1 blocks:")
    for i, b in enumerate(blocks1):
        log.info(f"Block {i}: {b.hex()}")

    log.info("Token2 blocks:")
    for i, b in enumerate(blocks2):
        log.info(f"Block {i}: {b.hex()}")

    # Step 3: Forge new token
    # Take block 0 and 1 from token1 (includes up to '"admin": ')
    # Take block 1 from token2 (starts with 'true}')
    forged = blocks1[0] + blocks1[1] + blocks2[1]

    log.success("Forged token (Base64): " + b64encode(forged).decode())

    # Step 4: Use forged token to get the flag
    response = get_flag(forged)
    print(response.decode(errors='ignore'))


if __name__ == "__main__":
    main()
