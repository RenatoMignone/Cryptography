from Crypto.Hash import SHA256

if __name__ == "__main__":
    #now the first step is to create a hash object
    hash_generator = SHA256.new()

    #here we are still passing the data as binary string
    hash_generator.update(b"text to hash")

    hash_generator.update(b" even more text")

    # now we can output the result and the hash generator digest
    print(hash_generator.hexdigest())
    print(hash_generator.digest())


    #we can already pass the data directly as input string
    hash_generator = SHA256.new(data=b"initial bytes")

    hash_generator.update(b"text to hash")

    hash_generator.update(b" even more text")

    print(hash_generator.hexdigest())
    print(hash_generator.digest())
