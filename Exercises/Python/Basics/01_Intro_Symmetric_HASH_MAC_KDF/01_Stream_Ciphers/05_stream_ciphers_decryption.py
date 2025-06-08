from Crypto.Cipher import Salsa20
from Crypto.Random import get_random_bytes
import base64

if __name__ == '__main__':
    
    # Create a Salsa20 key
    key = get_random_bytes(Salsa20.key_size[1])

    #create the nonce
    nonce = get_random_bytes(8)

    #now we read the info from one file with a fixed amount of bytes
    #and then we encrypt it
    cipher = Salsa20.new(key=key, nonce=nonce)

    #we open the output file for the ciphertext
    f_output = open("enc.enc", "wb")

    #we store space for the ciphertext
    ciphertext = b''

    with open(__file__,"rb") as f_input:
        #we read from the file in chunks of 1024 bytes
        plaintext = f_input.read(1024)

        while plaintext:
            #we need to compute the ciphertext
            ciphertext = cipher.encrypt(plaintext)
            #we now write the ciphertext to the output file
            #so we do not need to store all the ciphertext in memory
            f_output.write(ciphertext)

            #we read the next chunk of plaintext
            plaintext = f_input.read(1024)

    print("Nonce:" + base64.b64encode(cipher.nonce).decode())
    