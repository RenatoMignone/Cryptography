from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

import base64
import json

if __name__ == "__main__":
    
    #we create now the headers
    header = b'this only needs authentication'
    #we create the payload
    payload = b'this also needs confidentiality'

    #we now create the key
    key = get_random_bytes(AES.key_size[2])

    #now we create the cipher object
    #we now use the GCM mode to perform the authenticated encryption
    #we do not explicitely define the IV, we let the cipher object do it for us
    cipher = AES.new(key, AES.MODE_GCM)

    #the update is only needed for the header
    cipher.update(header)

    #instead the encrypt method is used for the payload
    #this function returns two values, the ciphertext and the tag
    ciphertext, tag = cipher.encrypt_and_digest(payload)

    #the entries in this JSON are:
    #nonce, header, ciphertext and tag
    #the nonce is the IV used for the encryption
    #the header is the data that was authenticated
    #the ciphertext is the encrypted payload
    #the tag is the authentication tag
    json_keys = ['nonce', 'header', 'ciphertext', 'tag']
    json_values = [cipher.nonce, header, ciphertext, tag]

    #here we are using the base64 module to encode the values
    #this is needed because the values are binary
    #and we need to convert them to a string format
    json_b64_values = [base64.b64encode(value).decode() for value in json_values]

    #here we are using the constructor of a dictionary
    #to create the JSON object
    #we are using the zip function to create pairs of keys and values
    #and then we are using the dict function to create the dictionary
    json_obj = json.dumps(dict(zip(json_keys, json_b64_values)))

    print('JSON object:')
    print(json_obj)


    #------------------------------------------------------------------------
    #now we assume that we are at the receiver side

    b64_obj = json.loads(json_obj)
    #we assume that the verifies knows the key values
    json_keys = ['nonce', 'header', 'ciphertext', 'tag']

    #here we are creating the dictionary with the keys names
    jv = {key: base64.b64decode(b64_obj[key]) for key in json_keys}

    #here we need to pass the nonce to the cipher object
    #this is the IV used for the encryption
    cipher_receiver = AES.new(key, AES.MODE_GCM, nonce=jv['nonce'])

    #here we need to pass the header to the cipher object
    #this is the data that was authenticated
    cipher_receiver.update(jv['header'])

    #then we need to decrypt the payload
    #and verify the authentication tag
    #this function returns the decrypted payload
    #and verifies the authentication tag
    try:
        cipher_receiver.decrypt_and_verify(jv['ciphertext'], jv['tag'])
        print('Decrypted payload:')
        print(cipher_receiver.decrypt(jv['ciphertext']))
    except (ValueError, KeyError):
        print('Decryption failed')
