# Import socket library for network communication
import socket
# Import sys library for system-specific parameters and functions
import sys

# Import AES cipher from PyCryptodome
from Crypto.Cipher import AES
# Import pad utility for PKCS7 padding
from Crypto.Util.Padding import pad
# Import getrandbits for random bit generation
from Crypto.Random.random import getrandbits

# Import secret key from local file
from mysecrets import ecb_oracle_key
# Import host and port configuration
from myconfig import HOST,PORT

#----------------------------------------------------------
# Define constant for ECB mode
ECB_MODE = 0
# Define constant for CBC mode
CBC_MODE = 1

#----------------------------------------------------------
# Create a TCP/IP socket
# The first input is the address family (IPv4)
# The second input is the socket type (SOCK_STREAM for TCP)
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
print('Socket created')

try:
    # Bind the socket to the host and port
    s.bind((HOST, PORT))
except socket.error as msg:
    # Print error and exit if binding fails
    print('Bind failed. Error Code : ' + str(msg[0]) + ' Message ' + msg[1])
    sys.exit()
print('Socket bind complete')

# Listen for incoming connections (up to 10 in the queue)
s.listen(10)
print('Socket now listening')

#----------------------------------------------------------
# Wait to accept a connection - blocking call
while 1:
    # Accept a new connection
    # The accept() method returns a new socket object representing the connection
    # and a tuple holding the address of the client
    conn, addr = s.accept()
    print('A new encryption requested by ' + addr[0] + ':' + str(addr[1]))

    # Select a mode of operation: ECB = 0, CBC = 1 (randomly)
    selected_mode = getrandbits(1)
    print("Seledcted mode = ",end='')
    if(selected_mode == ECB_MODE):
        # Print selected mode
        print("ECB")
    else:
        print("CBC")

    # Receive the chosen plaintext from the user
    input0 = conn.recv(1024).decode()
    # Construct a message with the received plaintext
    message = "This is what I received: " + input0 + " -- END OF MESSAGE"
    print("Plaintext: " +message)

    # Encrypt plaintext with chosen mode
    if(selected_mode == ECB_MODE):
        # Create AES cipher in ECB mode
        cipher = AES.new( ecb_oracle_key, AES.MODE_ECB )
    else:
        # Create AES cipher in CBC mode
        cipher = AES.new( ecb_oracle_key, AES.MODE_CBC )

    # Pad the message to AES block size
    message = pad(message.encode(),AES.block_size)
    # Encrypt the padded message
    ciphertext = cipher.encrypt(message)
    # Send ciphertext to the client
    conn.send(ciphertext)

    # Close the connection
    conn.close()

# Close the socket (unreachable code in this loop)
s.close()
