from pwn import *

def xor(a, b):
    return bytes([x ^ y for x, y in zip(a, b)])

conn = remote('130.192.5.212', 6531)

for _ in range(128):
    # Wait for the challenge number
    conn.recvuntil(f'Challenge #{_}\n'.encode())
    
    # Read the OTP
    otp_line = conn.recvline().decode().strip()
    otp_hex = otp_line.split(': ')[1]
    otp = bytes.fromhex(otp_hex)
    
    # Split OTP into two 16-byte blocks
    otp1, otp2 = otp[:16], otp[16:]
    
    # Choose a 16-byte block (all zeros here)
    block = b'\x00' * 16
    
    # Compute data parts
    data_part1 = xor(otp1, block)
    data_part2 = xor(otp2, block)
    data = data_part1 + data_part2
    
    # Send the input data
    conn.sendlineafter(b'Input: ', data.hex().encode())
    
    # Receive the ciphertext
    output_line = conn.recvline().decode().strip()
    cipher_hex = output_line.split(': ')[1]
    cipher = bytes.fromhex(cipher_hex)
    
    # Split cipher into two blocks and compare
    cipher1, cipher2 = cipher[:16], cipher[16:]
    mode = 'ECB' if cipher1 == cipher2 else 'CBC'
    
    # Send the guessed mode
    conn.sendlineafter(b'(ECB, CBC)\n', mode.encode())
    
    # Check response
    resp = conn.recvline().decode().strip()
    if 'OK' not in resp:
        print(f"Failed at challenge {_}")
        exit()

# Get the flag
conn.recvuntil(b'The flag is: ')
flag = conn.recvline().decode().strip()
print(f"Flag: {flag}")

conn.close()