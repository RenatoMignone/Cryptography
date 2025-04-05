from Crypto.Random import get_random_bytes
from Crypto.Cipher import ChaCha20
import base64

if __name__ == "__main__":

    plaintext = b'This is the secret message...'

    #now we need to use the ChaCha20 class
    #We as firs step need to generate a random key
    key = get_random_bytes(ChaCha20.key_size)  

    #here we are initializing the cipher
    #Here the parameters needs to be passed by specifying the keyword
    #so not just by the order of the parameters
    cipher = ChaCha20.new(key=key)  # create a new cipher object

    #We now need to encrypt the plaintext
    ciphertext = cipher.encrypt(plaintext)  # encrypt the plaintext

    #Here the base64 is used to encode the ciphertext and then decode it to utf-8
    print("\nCiphertext:" + base64.b64encode(ciphertext).decode('utf-8'))

    #We can also print the nonce here, obtained passing the encryption object
    #The nonce is used to make the encryption unique
    #This nonce of ChaCha20 is pretty short
    print("\nNonce:" + base64.b64encode(cipher.nonce).decode('utf-8'))
