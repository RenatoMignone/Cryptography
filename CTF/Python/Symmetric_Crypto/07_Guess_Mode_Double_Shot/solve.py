#################################################################################
#Guess the mode. Now you need to reason about how modes work. 
# Ask a second encryption to confirm your hypothesis...

# nc 130.192.5.212 6532

#################################################################################
#FLAG: CRYPTO25{c15fa569-562d-4531-b58b-75fe687c4b0a}
#################################################################################

#################################################################################
# Attack: ECB vs CBC Understanding
#################################################################################


from pwn import *

def solve():

    conn = remote('130.192.5.212', 6532)
    # 32 bytes of zeros in hex
    zero_input = '00' * 32

    # Loop for 128 challenges
    for _ in range(128):

        conn.recvuntil(b'Challenge #')
        
        # Send first input of 32 zeros
        conn.sendlineafter(b'Input: ', zero_input)

        # Receive and parse first ciphertext
        ct1 = conn.recvline().strip().decode().split(': ')[1]
        
        # Send second input of 32 zeros
        conn.sendlineafter(b'Input: ', zero_input)
        
        # Receive and parse second ciphertext
        ct2 = conn.recvline().strip().decode().split(': ')[1]
        
        # Determine mode based on ciphertexts
        mode = 'ECB' if ct1 == ct2 else 'CBC'
        # Send guessed mode to server
        conn.sendlineafter(b'What mode did I use? (ECB, CBC)\n', mode.encode())
        
        # Check if the response is OK
        res = conn.recvline()
        if b'Wrong' in res:
            print("Failed")
            break
        else:
            print("OK")

    # Get flag
    print(conn.recvall().decode())

if __name__ == '__main__':
    solve()