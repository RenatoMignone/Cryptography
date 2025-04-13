from Crypto.Cipher import AES                   # Import AES cipher from PyCryptodome library
from Crypto.Random import get_random_bytes      # Import function to generate random bytes
from secret import flag                         # Import the flag (presumably a secret value)
import random                                   # Import random module for random selection

# Mapping of mode names to AES mode constants
modes_mapping = {
    "ECB": AES.MODE_ECB,
    "CBC": AES.MODE_CBC
}


class RandomCipherRandomMode():
    def __init__(self):
        # Initialize the cipher with a random mode (either ECB or CBC)
        modes = [AES.MODE_ECB, AES.MODE_CBC]
        self.mode = random.choice(modes)        # Randomly select a mode
        self.key = get_random_bytes(32)         # Generate a random 32-byte key
        if self.mode == AES.MODE_ECB:
            # For ECB mode, no IV is required
            self.iv = None
            self.cipher = AES.new(key=self.key, mode=self.mode)  # Create AES cipher in ECB mode
        else:
            # For CBC mode, generate a random 16-byte IV
            self.iv = get_random_bytes(16)
            self.cipher = AES.new(key=self.key, iv=self.iv, mode=self.mode)  # Create AES cipher in CBC mode

    def encrypt(self, data):
        # Encrypt the provided data using the initialized cipher
        return self.cipher.encrypt(data)

    def decrypt(self, data):
        # Decrypt the provided data using the initialized cipher
        return self.cipher.decrypt(data)


def main():
    # Main function to handle the challenge logic

    for i in range(128):  # Loop through 128 challenges
        cipher = RandomCipherRandomMode()  # Create a new cipher with a random mode

        print(f"Challenge #{i}")  # Display the challenge number

        otp = get_random_bytes(32)                              # Generate a random 32-byte OTP (one-time pad)
        print(f"The otp I'm using: {otp.hex()}")                # Display the OTP in hexadecimal format
        data = bytes.fromhex(input("Input: ").strip())          # Read user input as hexadecimal and convert to bytes
        if len(data) != 32:
            # Ensure the input data is exactly 32 bytes long
            print("Data must be 32 bytes long")
            return

        # XOR the input data with the OTP
        data = bytes([d ^ o for d, o in zip(data, otp)])
        print(f"Output: {cipher.encrypt(data).hex()}")          # Encrypt the XORed data and display the result in hex

        # Ask the user to guess the mode used by the cipher
        mode_test = input(f"What mode did I use? (ECB, CBC)\n")
        if mode_test in modes_mapping.keys() and modes_mapping[mode_test] == cipher.mode:
            # If the guess is correct, proceed to the next challenge
            print("OK, next")
        else:
            # If the guess is incorrect, terminate the challenge
            print("Wrong, sorry")
            return

    # If all challenges are passed, reveal the flag
    print(f"The flag is: {flag}")


if __name__ == "__main__":
    main()  # Run the main function
