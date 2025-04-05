import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad

import json

if __name__ == '__main__':

    key = get_random_bytes(AES.key_size[0])
    IV = get_random_bytes(AES.block_size)

    #open the input file
    f_input = open(__file__, "rb")

    #allocate the cipher object
    cipher = AES.new(key, AES.MODE_CBC, IV) 

    #in this case we are going to read the entire file at once
    ciphertext = cipher.encrypt(pad(f_input.read(), AES.block_size))

    #now we write the ciphertext to the output file
    f_output = open("enc.enc", "wb")
    f_output.write(ciphertext)
    
    f_output.close()
    f_input.close()

    print(base64.b64encode(IV).decode())



    #now we insert all the information needed inside a single data structure
    #the best way to do it is by means of the JSONs

    result = json.dumps({
        "key": base64.b64encode(key).decode(),
        "IV": base64.b64encode(IV).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode()
    }, indent=4)


    # print(result)



    #----------------------------------------------------------------
    #now we are going to decrypt the file
    #----------------------------------------------------------------

    b64_output = json.loads(result)

    iv = base64.b64decode(b64_output["IV"])

    ciphertext = base64.b64decode(b64_output["ciphertext"])

    cipher_dec = AES.new(key, AES.MODE_CBC, iv)

    plaintext = cipher_dec.decrypt(ciphertext)

    print("plaintext: ", plaintext.decode())
