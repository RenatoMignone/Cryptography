from Crypto.Hash import SHA3_256

if __name__ == "__main__":

    # Create a hash object 
    hash_generator = SHA3_256.new()

    #-------------------------------------------------------------------------
    #now we read the file in binary mode
    with open(__file__,"rb") as f_input:
        #we pass to the generator the whole content of the file 
        hash_generator.update(f_input.read())

    # now we can output the result and the hash generator digest
    print(hash_generator.hexdigest())


    #-------------------------------------------------------------------------
    #we could also do the same process without the rb of the file 
    #now we read the file in binary mode
    with open(__file__) as f_input:
        #we pass to the generator the whole content of the file 
        #in this case we need to encode the string to bytes
        #since we are reading it as a text file
        hash_generator.update(f_input.read().encode())

    # now we can output the result and the hash generator digest
    print(hash_generator.hexdigest())
