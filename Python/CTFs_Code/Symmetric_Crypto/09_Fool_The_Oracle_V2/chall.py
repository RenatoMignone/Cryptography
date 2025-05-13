# Import AES cipher from PyCryptodome
from Crypto.Cipher import AES
# Import padding/unpadding utilities for block ciphers
from Crypto.Util.Padding import pad, unpad
# Import function to generate random bytes
from Crypto.Random import get_random_bytes
# Import the secret flag from a separate file
from secret import flag

# Assert that the flag length matches the expected format plus 36 extra characters
assert (len(flag) == len("CRYPTO25{}") + 36)

# Generate a random 24-byte key for AES encryption
key = get_random_bytes(24)
# Generate a random 5-byte padding
padding = get_random_bytes(5)
# Encode the flag as bytes
flag = flag.encode()


# Function to encrypt user input with random padding and the flag
def encrypt() -> bytes:
    # Read user input as a hex string, strip whitespace, and convert to bytes
    data = bytes.fromhex(input("> ").strip())
    # Concatenate the random padding, user data, and flag
    payload = padding + data + flag

    # Create a new AES cipher object in ECB mode
    cipher = AES.new(key=key, mode=AES.MODE_ECB)
    # Pad the payload and encrypt, then print the ciphertext as hex
    print(cipher.encrypt(pad(payload, AES.block_size)).hex())


# Main function to handle the user menu and commands
def main():
    # Define the menu string
    menu = \
        "What do you want to do?\n" + \
        "quit - quit the program\n" + \
        "enc - encrypt something\n" + \
        "help - show this menu again\n" + \
        "> "

    # Loop to process user commands
    while True:
        # Read user command
        cmd = input(menu).strip()

        # If user wants to quit, break the loop
        if cmd == "quit":
            break
        # If user wants help, show the menu again
        elif cmd == "help":
            continue
        # If user wants to encrypt, call the encrypt function
        elif cmd == "enc":
            encrypt()


# Run the main function if this script is executed directly
if __name__ == '__main__':
    main()
