# Import the random module for pseudo-random number generation
import random
# Import ChaCha20 cipher from PyCryptodome
from Crypto.Cipher import ChaCha20
# Import utility to convert long integers to bytes
from Crypto.Util.number import long_to_bytes
# Import the secret flag and random key from a separate file
from secret import flag, randkey

# Initialize the nonce variable with a dummy value
nonce = -1


# Function to encrypt a message with ChaCha20 and update the nonce
def encrypt_and_update(msg, nonce):
    # Create a new ChaCha20 cipher object with the given key and nonce
    cipher = ChaCha20.new(key=randkey, nonce=long_to_bytes(nonce))
    # Generate a new random 12-byte nonce for the next encryption
    nonce = random.getrandbits(12*8)
    # Encrypt the message (converted to bytes) and return the ciphertext
    return cipher.encrypt(msg.encode())


# Main function to handle user interaction and encryption
def main():
    # Prompt user for a seed value to initialize the random number generator
    seed = int(input(
        "Hi, our system doesn't support analogic entropy... so please give a value to initialize me!\n> "))
    # Seed the random number generator with the user-provided value
    random.seed(seed)
    # Generate a random 12-byte nonce
    nonce = random.getrandbits(12*8)

    # Inform the user that the system is ready and print the encrypted flag
    print("OK! I can now give you the encrypted secret!")
    print(encrypt_and_update(flag, nonce).hex())

    # Ask the user if they want to encrypt more messages
    confirm = input("Do you want to encrypt something else? (y/n)")
    # Loop to allow multiple encryptions until the user says 'n'
    while confirm.lower() != 'n':
        # If user wants to encrypt, prompt for a message and print the ciphertext
        if confirm.lower() == 'y':
            msg = input("What is the message? ")
            print(encrypt_and_update(msg, nonce).hex())
        # Ask again if the user wants to encrypt more messages
        confirm = input("Do you want to encrypt something else? (y/n)")


# Run the main function if this script is executed directly
if __name__ == '__main__':
    main()
