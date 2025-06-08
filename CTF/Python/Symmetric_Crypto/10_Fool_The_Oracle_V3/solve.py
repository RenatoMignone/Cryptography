#################################################################################
#...even more complex now...

#nc 130.192.5.212 6543

#################################################################################
#FLAG: CRYPTO25{e3ab2169-39d5-43aa-bde7-02286c2e2e56}
#################################################################################

#################################################################################
# Attack: Adaptive Chosen Plaintext Attack
#################################################################################

#################################################################################
# Attack Description: The attacker aligns their input after the random prefix 
# and recovers the flag one byte at a time using the ECB oracle.
#################################################################################

from pwn import remote
import sys

#----------------------------------------------------------------
HOST, PORT = "130.192.5.212", 6543
BLOCK = 16
FLAG_LEN = 46

#----------------------------------------------------------------
def get_ct(io, pt_hex):
    io.recvuntil(b'> ')
    io.sendline(b'enc')
    io.recvuntil(b'> ')

    io.sendline(pt_hex.encode())

    # We return the value as bytes
    return bytes.fromhex(io.recvline().strip().decode())


#----------------------------------------------------------------
# Utility function to split data into blocks of given size
def split_blocks(data):
    # Return a list of blocks of length 'size'
    return [data[i:i+BLOCK] for i in range(0, len(data), BLOCK)]


#----------------------------------------------------------------
# finds out how many bytes you need to add to your input so that your controlled 
# data starts exactly at the beginning of an AES block
def find_align(io):
    # Try different paddings to find when two consecutive blocks are identical
    for pad in range(1,BLOCK):
        # Send a pattern of 'A's long enough to guarantee two identical blocks after alignment
        # By means of this input, for some value of pad, we will have 2 blocks of 'A's
        test = b'A' * (pad + 2*BLOCK)
        # Get the ciphertext blocks for this input
        blocks = split_blocks(get_ct(io, test.hex()))
        # Look for two identical consecutive blocks
        for i in range(len(blocks)-1):
            #if two blocks are equal, then we have found the alignment
            if blocks[i] == blocks[i+1]:
                # Return the padding needed and the block index where alignment occurs
                return pad, i


#----------------------------------------------------------------
def main():

    io = remote(HOST, PORT)
    # Find the required padding and the starting block index for aligned input
    pad_len, start_blk = find_align(io)

    print(f"Padding length: {pad_len}, Start block index: {start_blk}")

    # Buffer to store the recovered flag bytes
    recovered = b''

    # Loop over each byte of the flag to recover it one at a time
    for i in range(FLAG_LEN):

        # Calculate the padding needed to align the next unknown flag byte at the end of a block
        pad = pad_len + (BLOCK-1 - (len(recovered)%BLOCK))

        # Prepare the prefix to achieve the correct alignment
        prefix = b'A' * pad

        # Get the ciphertext for the aligned input (without the next flag byte)
        ct = get_ct(io, prefix.hex())

        # Determine which ciphertext block contains the next flag byte
        blk_idx = start_blk + (len(recovered)//BLOCK)

        # Extract the target ciphertext block to match against
        target = ct[blk_idx*BLOCK:(blk_idx+1)*BLOCK]

        # Try all possible byte values for the next flag byte
        for b in range(256):

            # Construct the guess: prefix + recovered flag so far + candidate byte
            guess = prefix + recovered + bytes([b])

            # Get the ciphertext for the guess
            guess_ct = get_ct(io, guess.hex())

            # Compare the relevant block to the target block
            if guess_ct[blk_idx*BLOCK:(blk_idx+1)*BLOCK] == target:
                # If they match, we have found the correct byte
                recovered += bytes([b])
                # Print the recovered byte to stdout
                print()
                break
    # Print the full recovered flag
    print(f"\n[+] Flag: {recovered.decode(errors='replace')}")


#----------------------------------------------------------------
if __name__ == "__main__":
    main()
