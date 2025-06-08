#################################################################################
#fool this new one...

#nc 130.192.5.212 6542

#################################################################################
#FLAG: CRYPTO25{ad3c6c1e-5cac-4c87-b5c3-a5dab511fee3}
#################################################################################

#################################################################################
# Attack: Adaptive Chosen Plaintext Attack
#################################################################################


from pwn import *

#-----------------------------------------------------------------
BLOCK = 16
HOST, PORT = "130.192.5.212", 6542
# We set PADD = 11 because the prefix is 5 bytes, and 5 + 11 = 16 (one block). 
# This lets us control the start of a block, which is essential for the ECB byte-at-a-time attack.
PADD = 11
# The length of the flag is known from the server
FLAG_LEN = 46

#-----------------------------------------------------------------
# Function to interact with the oracle and get ciphertext for a given plaintext
def get_ct(io, pt):
    # Send 'enc' command and plaintext (hex encoded), receive ciphertext (hex)
    io.sendlineafter(b"> ", b"enc")
    io.sendlineafter(b"> ", pt.hex().encode())
    return bytes.fromhex(io.recvline().strip().decode())


#-----------------------------------------------------------------
def main():
    io = remote(HOST, PORT)

    # Buffer to store the recovered flag bytes
    known = b""
    
    # Loop over each byte of the flag to recover it one at a time
    while len(known) < FLAG_LEN:

        # Calculate the padding needed to align the next unknown flag byte at the end of a block
        plen = (BLOCK - (len(known)%BLOCK) - 1) % BLOCK

        # Prepare the prefix to achieve the correct alignment
        # The prefix is aligned to ensure the next byte we want to guess is at the end of a block
        prefix = b"A"*(PADD+plen)

        # Determine which ciphertext block contains the next flag byte
        idx = 1 + len(known)//BLOCK

        # Get the ciphertext for the aligned input
        tgt = get_ct(io, prefix)

        # [idx*BLOCK:(idx+1)*BLOCK] this slices let us take only the interested block of the obtained ciphertext
        target = tgt[idx*BLOCK:(idx+1)*BLOCK]

        # Try all possible byte values for the next flag byte
        for b in range(256):

            # Here we are using the server as an oracle, the test plaintext is the prefix plus the guessed byte
            # So we are getting the ciphertext for the new tested value, and then we compare it with the target block
            test_ct = get_ct(io, prefix+known+bytes([b]))

            # Extract the relevant block from the ciphertext
            text_value = test_ct[idx*BLOCK:(idx+1)*BLOCK]

            # Compare the relevant block to the target block
            if text_value == target:
                # If they match, we have found the correct byte
                known += bytes([b])
                # Print the recovered bytes so far
                print(known.decode(errors="ignore"), end="\r")
                break
        else:
            # If no match is found, print an error and stop
            print("Failed to match next byte.")
            break
    # Print the full recovered flag
    print(f"\nFlag: {known.decode(errors='ignore')}")
    io.close()


#-----------------------------------------------------------------
if __name__ == "__main__":
    main()