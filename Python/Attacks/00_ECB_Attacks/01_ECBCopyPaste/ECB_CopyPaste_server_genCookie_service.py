# Import system-specific parameters and functions
import sys

# Import AES cipher and padding utilities
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
# Import socket library for networking
import socket
# Import the secret key for AES encryption
from mysecrets import ecb_oracle_key as key

# Import server configuration (host and port)
from myconfig import HOST,PORT

###############################
def profile_for(email):
    # Simulate a DB access to get user data and sanitize input
    email=email.replace('=','')
    email=email.replace('&','')

    # Create a dictionary with user profile fields
    dict = {}
    dict["email"] = email
    dict["UID"] = 10
    dict["role"] = "user"
    return dict

###############################
def encode_profile(dict):
    # Generate a string from user data dictionary
    """
    :type dict: dictionary
    """
    s = ""
    i=0
    n = len(dict.keys())
    print(n)
    for key in dict.keys():
        s+=key+"="+str(dict[key])
        if i < (n-1):
            s+="&"
            i+=1
    return s

###############################

def encrypt_profile(encoded_profile):
    # Encrypt the encoded profile using AES in ECB mode
    cipher = AES.new(key,AES.MODE_ECB)
    plaintext = pad(encoded_profile.encode(),AES.block_size)
    print(plaintext)
    return cipher.encrypt(plaintext)

###############################
def decrypt_msg(ciphertext):
    # Decrypt the ciphertext using AES in ECB mode
    cipher = AES.new(key,AES.MODE_ECB)
    return unpad(cipher.decrypt(ciphertext),AES.block_size)


if __name__ == '__main__':

    # Create a socket object
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print('Socket created')

    try:
        # Bind the socket to the host and port
        s.bind((HOST, PORT))
    except socket.error as msg:
        print('Bind failed. Error Code : ' + str(msg[0]) + ' Message ' + msg[1])
        sys.exit()
    print('Socket bind complete')

    # Start listening for incoming connections
    s.listen(10)
    print('Socket now listening')

    # Wait to accept a connection - blocking call
    while 1:
        # Accept a new connection
        conn, addr = s.accept()
        print('A new encryption requested by ' + addr[0] + ':' + str(addr[1]))

        # Receive email from the client
        email = conn.recv(1024)
        # Generate and encrypt user profile
        cookie = encrypt_profile(encode_profile(profile_for(email.decode())))

        print("Cookie: " + encode_profile(profile_for(email.decode())))

        # Send the encrypted profile (cookie) back to the client
        conn.send(cookie)
        # Close the connection
        conn.close()

    # Close the socket
    s.close()



