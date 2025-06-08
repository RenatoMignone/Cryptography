import hashlib
import hmac

from Crypto.Random import get_random_bytes

if __name__ == "__main__":

    dig_generator = hashlib.sha256()

    dig_generator.update(b"First chunk of data")

    print(dig_generator.hexdigest())


    secret = get_random_bytes(32)

    #we now create the HMAC object
    #so here as second parameter we are passing the message to hash
    #the third parameter is the hash function to use
    mac_generator = hmac.new(secret, b'message to hash', hashlib.sha256)

    print(mac_generator.hexdigest())