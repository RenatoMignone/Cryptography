from Crypto.Hash import SHA3_256
from Crypto.Random import get_random_bytes
from Crypto.Hash import HMAC

import json
import base64

if __name__ == "__main__": 

    msg = b'This is the message used in input'

    #we also give here a shared secret with another party
    # 256 bits
    secret = get_random_bytes(32)

    #to generate an HMAC we need to use a generator of HMACs
    # here for the algorithm we pass the reference to the function
    hmac_generator = HMAC.new(secret, digestmod=SHA3_256)

    #we generate now the HMAC
    hmac_generator.update(msg)

    #finally we can print the HMAC
    print("HMAC: ", hmac_generator.hexdigest())

    #we could also passs only some bytes of the data to the HMAC
    #in this case we pass only the first 5 bytes
    # hmac_generator.update(msg[:5])

    #print("HMAC: ", hmac_generator.hexdigest())


    #we now operate with the JSON
    #we create the dict for the secrets and the data
    obj = json.dumps({'message':msg.decode(),
                      'MAC': base64.b64encode(hmac_generator.digest()).decode(),
                    })
    
    print("JSON: ", obj)

    #------------------------------------------------------------------------------
    #we can now assume that the recipient has received the JSON
    #and he wants to decode it
    b64_obj = json.loads(obj)

    #now we have the same object of before
    hmac_verifier = HMAC.new(secret, digestmod=SHA3_256)

    #since these are strings and we need to transform them into bytes, we use
    hmac_verifier.update(b64_obj['message'].encode())

    #we inject a small modification into the MAC
    mac = bytearray(base64.b64decode(b64_obj['MAC'].encode()))
    #this one here is the modification
    mac[0] = 0

    #now we call the function to perform the verification
    #to perform the verification we pass it the MAC computed by the sender
    #since the one computed by the receiver is already in the object
    try:
        hmac_verifier.verify(mac)
        print("The MAC is valid")
    except ValueError:
        print("The MAC is not valid")
