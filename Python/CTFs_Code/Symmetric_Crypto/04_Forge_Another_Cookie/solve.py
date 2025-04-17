# Needless to say, you need the proper authorization cookie to get the flag

# nc 130.192.5.212 6552

from pwn import *
import sys
from Crypto.Util.number import long_to_bytes, bytes_to_long

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 exploit.py <REMOTE_IP> <REMOTE_PORT>")
        return

    host = sys.argv[1]
    port = int(sys.argv[2])

    # Step 1: Get the encrypted cookie with 'admin=false' in a known block
    p = remote(host, port)
    p.sendlineafter("Username: ", 'A' * 8)  # Aligns 'admin=false' to block 2
    encrypted_cookie = int(p.recvline().decode().strip())
    p.close()

    # Convert to bytes and split into blocks
    block_size = 16
    cookie_bytes = long_to_bytes(encrypted_cookie)
    blocks = [cookie_bytes[i:i+block_size] for i in range(0, len(cookie_bytes), block_size)]

    # Step 2: Generate a block for 'admin=true' (This requires knowing the encryption of 'admin=true' with padding)
    # This part is theoretical; in practice, you need to craft a username that forces this block.
    # For this example, we assume we have the correct block from a separate encryption.
    # Replace the second block (index 1) with the malicious block
    # For demonstration, this is a placeholder. Actual exploit requires calculating this block.
    malicious_block = b'\x00' * block_size  # Replace with actual encrypted block

    # Replace the block containing 'admin=false' with 'admin=true'
    blocks[1] = malicious_block

    # Reconstruct the malicious cookie
    malicious_cookie = b''.join(blocks)
    malicious_cookie_int = bytes_to_long(malicious_cookie)

    # Step 3: Submit the malicious cookie
    p = remote(host, port)
    p.sendlineafter("Username: ", 'dummy')  # Trigger the login to bypass menu
    p.sendlineafter("> ", 'flag')
    p.sendlineafter("Cookie: ", str(malicious_cookie_int))
    response = p.recvall()
    print(response.decode())

if __name__ == "__main__":
    main()