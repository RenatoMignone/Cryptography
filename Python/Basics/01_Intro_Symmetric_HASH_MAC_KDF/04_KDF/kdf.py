from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes


if __name__ == "__main__":
    
    #we generate a weak password
    password = b'WeakP4asswd'

    #now we need to call the scrypt function
    #to transform the password into a key
    #here teh second parameter is the salt 
    #the third parameter is the number of bytes composing the key
    #the fourth parameter is the N value, so the number of iterations
    #the fifth parameter is the r value, so the block size
    #the sixth parameter is the p value, so the parallelization factor
    key = scrypt(password, get_random_bytes(16), 16, N=2**14, r=8, p=1)

    print(key)