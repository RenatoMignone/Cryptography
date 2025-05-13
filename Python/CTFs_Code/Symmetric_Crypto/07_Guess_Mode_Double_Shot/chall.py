from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from secret import flag
import random

modes_mapping = {
    "ECB": AES.MODE_ECB,
    "CBC": AES.MODE_CBC
}


class RandomCipherRandomMode():
    def __init__(self):
        modes = [AES.MODE_ECB, AES.MODE_CBC]
        self.mode = random.choice(modes)
        self.key = get_random_bytes(32)
        if self.mode == AES.MODE_ECB:
            self.iv = None
            self.cipher = AES.new(key=self.key, mode=self.mode)
        else:
            self.iv = get_random_bytes(16)
            self.cipher = AES.new(key=self.key, iv=self.iv, mode=self.mode)

    def encrypt(self, data):
        return self.cipher.encrypt(data)

    def decrypt(self, data):
        return self.cipher.decrypt(data)


def main():

    for i in range(128):
        cipher = RandomCipherRandomMode()

        print(f"Challenge #{i}")

        # Initialize a 32-byte block of zeros
        data = b"\00"*32

        # Generate a random one-time pad (OTP) of the same length as data
        otp = get_random_bytes(len(data))

        # Loop for two rounds of input/output
        for _ in range(2):
            # Prompt user for input, read as hex string, and convert to bytes
            data = bytes.fromhex(input("Input: ").strip())
            # Check if input is exactly 32 bytes
            if len(data) != 32:
                print("Data must be 32 bytes long")
                return

            # XOR the input data with the OTP
            data = bytes([d ^ o for d, o in zip(data, otp)])
            # Encrypt the XORed data with the cipher and print the ciphertext as hex
            print(f"Output: {cipher.encrypt(data).hex()}")

        # Ask the user to guess the cipher mode used (ECB or CBC)
        mode_test = input(f"What mode did I use? (ECB, CBC)\n")
        # Check if the user's guess matches the actual mode
        if mode_test in modes_mapping.keys() and modes_mapping[mode_test] == cipher.mode:
            print("OK, next")
        else:
            print("Wrong, sorry")
            return

    # If all challenges are passed, print the flag
    print(f"The flag is: {flag}")


# Run the main function if this script is executed directly
if __name__ == "__main__":
    main()
