from pwn import remote

HOST, PORT = "130.192.5.212", 6543
BLOCK = 16
FLAG_LEN = 46  # Adjust if flag length is different

def menu_enc(io):
    io.recvuntil(b'> ')
    io.sendline(b'enc')
    io.recvuntil(b'> ')

def get_ct(io, pt_hex):
    menu_enc(io)
    io.sendline(pt_hex.encode())
    return bytes.fromhex(io.recvline().strip().decode())

def split_blocks(data, size=BLOCK):
    return [data[i:i+size] for i in range(0, len(data), size)]

def find_align(io):
    # Find how many bytes to pad so that our input starts at a block boundary
    for pad in range(1, BLOCK+1):
        test = b'A' * (pad + 2*BLOCK)
        ct = get_ct(io, test.hex())
        blocks = split_blocks(ct)
        for i in range(len(blocks)-1):
            if blocks[i] == blocks[i+1]:
                return pad, i
    raise Exception("Alignment not found")

def main():
    io = remote(HOST, PORT)
    pad_len, start_blk = find_align(io)
    print(f"Padding length: {pad_len}, Start block index: {start_blk}")

    recovered = b''
    for i in range(FLAG_LEN):
        pad = pad_len + (BLOCK-1 - (len(recovered)%BLOCK))
        prefix = b'A' * pad
        ct = get_ct(io, prefix.hex())
        blk_idx = start_blk + (len(recovered)//BLOCK)
        target = ct[blk_idx*BLOCK:(blk_idx+1)*BLOCK]
        for b in range(256):
            guess = prefix + recovered + bytes([b])
            guess_ct = get_ct(io, guess.hex())
            if guess_ct[blk_idx*BLOCK:(blk_idx+1)*BLOCK] == target:
                recovered += bytes([b])
                print(recovered.decode(errors='replace'), end='\r')
                break
    print(f"\n[+] Flag: {recovered.decode(errors='replace')}")

if __name__ == "__main__":
    main()
