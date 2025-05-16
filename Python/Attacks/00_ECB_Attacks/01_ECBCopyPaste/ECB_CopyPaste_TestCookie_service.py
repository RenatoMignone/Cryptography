# Import system-specific parameters and functions
import sys
# Import socket library for networking
import socket

# Import AES cipher and padding utilities
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Import the secret key for AES encryption
from mysecrets import ecb_oracle_key as key
# Import server configuration (host, port, delta port)
from myconfig import HOST,PORT,DELTA_PORT

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
    # Encrypt the encoded profile using AES ECB mode
    cipher = AES.new(key,AES.MODE_ECB)
    plaintext = pad(encoded_profile.encode(),AES.block_size)
    print(plaintext)
    return cipher.encrypt(plaintext)

###############################
def decrypt_msg(ciphertext):
    # Decrypt the ciphertext and remove padding
    cipher = AES.new(key,AES.MODE_ECB)
    return unpad(cipher.decrypt(ciphertext),AES.block_size)

# --------------------------

if __name__ == '__main__':

    # Create a TCP/IP socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print('Socket created')

    try:
        # Bind the socket to the host and port (with DELTA_PORT offset)
        s.bind((HOST, PORT+DELTA_PORT))
    except socket.error as msg:
        print('Bind failed. Error Code : ' + str(msg[0]) + ' Message ' + msg[1])
        sys.exit()
    print('Socket bind complete')

    # Listen for incoming connections
    s.listen(10)
    print('Socket now listening')

    # Wait to accept a connection - blocking call
    while 1:
        # Accept a new connection
        conn, addr = s.accept()
        print('A new encryption requested by ' + addr[0] + ':' + str(addr[1]))

        # Receive the encrypted cookie from the client
        received_cookie = conn.recv(1024)
        # Create a new AES cipher for decryption
        cipher_dec = AES.new(key,AES.MODE_ECB)

        try:
            # Decrypt and unpad the received cookie
            decrypted = unpad(cipher_dec.decrypt(received_cookie),AES.block_size)
        except ValueError:
            # Handle wrong padding error
            print("Wrong padding")
            continue

        # Print the decrypted profile
        print(decrypted)

        # Check if the user is an admin by searching for 'role=admin'
        if b'role=admin' in decrypted:
            print("You are an admin!")
            conn.send("You are an admin!".encode())
        else:
            # Extract and print a welcome message for normal users
            i1 = decrypted.index(b'=')
            i2 = decrypted.index(b',')
            msg = "welcome"+decrypted[i1:i2].decode('utf-8')
            print("You are a normal user")
            print(msg)
            conn.send(msg.encode())

        # Close the connection
        conn.close()

# Close the socket (unreachable code in this loop)
s.close()



