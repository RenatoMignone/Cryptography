# Import AES cipher from PyCryptodome
from Crypto.Cipher import AES
# Import function to generate random bytes
from Crypto.Random import get_random_bytes
# Import the secret flag from a separate file
from secret import flag

# Generate a random 16-byte key for AES encryption
key = get_random_bytes(16)
# Define the special value 'leak' as a bytes object
leak = b"mynamesuperadmin"


# Function to create a new AES cipher in CBC mode with a random IV
def make_cipher():
    # Generate a random 16-byte IV
    IV = get_random_bytes(16)
    # Create a new AES cipher object in CBC mode with the key and IV
    cipher = AES.new(key, AES.MODE_CBC, IV=IV)
    # Return the IV and cipher object
    return IV, cipher


# Function to encrypt a user-provided 16-byte value (not equal to 'leak')
def encrypt():
    # Prompt user for input to encrypt (hex string)
    string = input("What do you want to encrypt?\n> ")
    # Convert input hex string to bytes
    string = bytes.fromhex(string)
    # Check if input is exactly 16 bytes
    if len(string) != 16:
        print("Sorry, you can encrypt only 16 bytes!")
        return

    # Prevent encryption of the special 'leak' value
    if leak == string:
        print("Sorry, you can't encrypt that!")
        return

    # Create a new cipher and IV
    IV, cipher = make_cipher()
    # Encrypt the input string
    encrypted = cipher.encrypt(string)

    # Print the IV and encrypted value as hex strings
    print(F"IV: {IV.hex()}\nEncrypted: {encrypted.hex()}\n")


# Function to decrypt a user-provided ciphertext with a user-provided IV
def decrypt():
    # Prompt user for ciphertext to decrypt (hex string)
    string = input("What do you want to decrypt?\n> ")
    # Convert input hex string to bytes
    string = bytes.fromhex(string)

    # Prompt user for IV (hex string)
    IV = input("Gimme the IV\n> ")
    # Convert IV hex string to bytes
    IV = bytes.fromhex(IV)

    # Prevent decryption if IV is equal to 'leak'
    if (IV == leak):
        print("Nice try...")
        return

    # Create a new AES cipher object in CBC mode with the key and IV
    cipher = AES.new(key, AES.MODE_CBC, IV=IV)

    # Decrypt the ciphertext
    decrypted = cipher.decrypt(string)
    # If decrypted value matches 'leak', print the flag
    if leak == decrypted:
        print(f"Good job. Your flag: {flag}")
    else:
        # Otherwise, print the decrypted value as hex
        print(f"Mh, a normal day.\nDecrypted: {decrypted.hex()}")


# Main program entry point
if __name__ == '__main__':
    # Define the menu string
    menu = \
        "What do you want to do?\n" + \
        "quit - quit the program\n" + \
        "enc - encrypt something\n" + \
        "dec - decrypt something\n" + \
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
        # If user wants to decrypt, call the decrypt function
        elif cmd == "dec":
            decrypt()
