from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


if __name__ == '__main__':

    #This is an example of how we could generate an IV
    IV = get_random_bytes(AES.block_size)

    #we now need to geneate a key
    #for the generation of the key we might not know the key size
    #so we will use a function to generate a key of the right size
    #the AES.key_size[2] is the largest key size we can use
    key = get_random_bytes(AES.key_size[2])


    #Now we are creating the plaintext that is not big 32 bytes
    plaintext = b'Unaligned string...'
    
    #we can see that the length of the plaintext is not a multiple of the block size
    print(len(plaintext))
    print("\n")

    #We can now create the cipher object
    cipher_enc = AES.new(key, AES.MODE_CBC, IV)


    #We need to pad the plaintext to be a multiple of the block size
    #This is important because the AES algorithm works with byte strings of 16 bytes
    padded_data = pad(plaintext, AES.block_size)
    #After having addedd the padding to the data we can print them and see the result
    print(padded_data)
    print("\n")

    #Now the object is ready, and we can use it to encrypt the data
    ciphertext = cipher_enc.encrypt(padded_data)
    print(ciphertext)
    print("\n")


    #Now we are creating the decryption object
    #the parameters are the same as the encryption object, otherwise the decryption will not work
    cipher_dec = AES.new(key, AES.MODE_CBC, IV)

    #Now we can use the decrypt function to decrypt the data
    #the result will be the same as the plaintext
    decrypted_data = cipher_dec.decrypt(ciphertext)

    #We need to remove the padding from the decrypted data
    #We can use the unpad function to do this
    decrypted_data = unpad(decrypted_data, AES.block_size)
    print(decrypted_data)
    print("\n")

