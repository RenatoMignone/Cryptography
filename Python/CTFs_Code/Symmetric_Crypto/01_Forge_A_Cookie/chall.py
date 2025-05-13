# Import ChaCha20 cipher from PyCryptodome
from Crypto.Cipher import ChaCha20
# Import function to generate random bytes
from Crypto.Random import get_random_bytes
# Import the secret flag from a separate file
from secret import flag
# Import JSON module for encoding/decoding
import json
# Import base64 module for encoding/decoding binary data
import base64

# Generate a random 32-byte key for ChaCha20 encryption
key = get_random_bytes(32)


# Function to create a new ChaCha20 cipher with a random nonce
def make_cipher():
    # Generate a random 12-byte nonce
    nonce = get_random_bytes(12)
    # Create a new ChaCha20 cipher object with the key and nonce
    cipher = ChaCha20.new(key=key, nonce=nonce)
    # Return the nonce and cipher object
    return nonce, cipher


# Function to generate a user token for a given username
def get_user_token(name):
    # Create a new cipher and get its nonce
    nonce, cipher = make_cipher()
    # Create a JSON string with the username
    token = json.dumps({
        "username": name
    })
    # Print the JSON token (for debugging)
    print(token)
    # Encrypt the JSON token using the cipher
    enc_token = cipher.encrypt(token.encode())
    # Encode the nonce and encrypted token in base64 and return as a string
    return f"{base64.b64encode(nonce).decode()}.{base64.b64encode(enc_token).decode()}"


# Function to check if a user token grants admin access
def check_user_token(token):
    # Split the token into nonce and encrypted token parts
    nonce, token = token.split(".")
    # Decode the nonce from base64
    nonce = base64.b64decode(nonce)
    # Create a new ChaCha20 cipher with the key and nonce
    cipher = ChaCha20.new(key=key, nonce=nonce)
    # Decrypt the encrypted token using the cipher
    dec_token = cipher.decrypt(base64.b64decode(token))

    # Parse the decrypted token as JSON to get the user dictionary
    user = json.loads(dec_token)

    # Check if the user dictionary has "admin" set to True
    if user.get("admin", False) == True:
        # If so, return True (admin access granted)
        return True
    else:
        # Otherwise, return False (admin access denied)
        return False


# Function to prompt the user for a token and print the flag if admin
def get_flag():
    # Ask the user to input their token
    token = input("What is your token?\n> ").strip()
    # Check if the token grants admin access
    if check_user_token(token):
        # If admin, print a success message and the flag
        print("You are admin!")
        print(f"This is your flag!\n{flag}")
    else:
        # If not admin, print an error message and exit
        print("HEY! WHAT ARE YOU DOING!?")
        exit(1)


# Main program execution
if __name__ == "__main__":
    # Ask the user for their name
    name = input("Hi, please tell me your name!\n> ").strip()
    # Generate a token for the user
    token = get_user_token(name)
    # Print the generated token
    print("This is your token: " + token)

    # Display the menu of options to the user
    menu = \
        "What do you want to do?\n" + \
        "quit - quit the program\n" + \
        "help - show this menu again\n" + \
        "flag - get the flag\n" + \
        "> "
    # Enter an infinite loop to process user commands
    while True:
        # Get the user's command
        cmd = input(menu).strip()

        # If the command is "quit", exit the loop
        if cmd == "quit":
            break
        # If the command is "help", redisplay the menu
        elif cmd == "help":
            continue
        # If the command is "flag", attempt to get the flag
        elif cmd == "flag":
            get_flag()
