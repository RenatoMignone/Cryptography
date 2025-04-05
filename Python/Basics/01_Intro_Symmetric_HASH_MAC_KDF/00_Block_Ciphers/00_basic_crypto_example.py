from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES


if __name__ == '__main__':

    #This is an example of how we could generate an IV
    IV = get_random_bytes(AES.block_size)

    #we now need to geneate a key
    #for the generation of the key we might not know the key size
    #so we will use a function to generate a key of the right size
    #the AES.key_size[2] is the largest key size we can use
    key = get_random_bytes(AES.key_size[2])

    #By using the b prefix we can create a byte string
    #this is important because the AES algorithm works with byte strings
    #Here if we execut ethe len(plaintext) we will see that the length is 32
    #this is important because the AES algorithm works with byte strings of 16 bytes
    plaintext = b'These are the data to encrypt !!'


    #We can now create the cipher object
    #The parameters of this new function are the key, the mode of operation and the IV
    cipher_enc = AES.new(key, AES.MODE_CBC, IV)

    #now the object is ready, and we can use it to encrypt the data
    #the function encrypt used over the cipher object will encrypt the data
    ciphertext = cipher_enc.encrypt(plaintext)

    print(ciphertext)

    print("\n")

    #Now we are creating the decryption object
    #the parameters are the same as the encryption object, otherwise the decryption will not work
    cipher_dec = AES.new(key, AES.MODE_CBC, IV)

    #Now we can use the decrypt function to decrypt the data
    #the result will be the same as the plaintext
    decrypted_data = cipher_dec.decrypt(ciphertext)
    print(decrypted_data)
