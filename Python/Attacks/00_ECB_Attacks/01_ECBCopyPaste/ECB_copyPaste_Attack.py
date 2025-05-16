# Import AES cipher for encryption/decryption
from Crypto.Cipher import AES
# Import padding utility for block alignment
from Crypto.Util.Padding import pad

# Import configuration variables for server connection
from myconfig import HOST, PORT, DELTA_PORT

# --------------------------

# Set environment variable to allow pwntools to run in IDEs
import os
os.environ['PWNLIB_NOTERM'] = 'True'  # Configuration patch to allow pwntools to be run inside of an IDE
# Set environment variable to silence pwntools output
os.environ['PWNLIB_SILENT'] = 'True'

# --------------------------

# Import pwntools for remote connection
from pwn import *

# Import functions to generate and encode user profiles
from ECB_CopyPaste_server_genCookie_service import profile_for,encode_profile

# --------------------------

if __name__ == '__main__':
    # Connect to the server that generates encrypted cookies
    server_gencookies = remote(HOST,PORT)
    # Prepare a normal email address as bytes
    email = b'aaaaaaa@b.com'

    # Send the email to the server to get a cookie
    server_gencookies.send(email)
    # Receive the encrypted cookie from the server
    encrpyted_cookie = server_gencookies.recv(1024)
    # Print the encrypted cookie for inspection
    print(encrpyted_cookie)

    # Locally encode the profile for the same email (for comparison)
    cookie_info = encode_profile(profile_for(email.decode()))
    # Print the encoded profile
    print(cookie_info)
    # Print the first 16 bytes (first block) of the encoded profile
    print(cookie_info[0:16])
    # Print the second 16 bytes (second block) of the encoded profile
    print(cookie_info[16:32])

    # --------------------------

    # Prepare a padded 'admin' block to align with AES block size
    padded_admin = b'A'*10 + pad( b'admin', AES.block_size)
    # Locally encode the profile for the padded admin email
    cookie_info = encode_profile(profile_for(padded_admin.decode()))
    # Print the first 16 bytes (first block) of the encoded profile
    print(cookie_info[0:16])
    # Print the second 16 bytes (second block) of the encoded profile as bytes
    print(cookie_info[16:32].encode())
    # Close the connection to the cookie generation server
    server_gencookies.close()

    # --------------------------

    # Reconnect to the server to get the encrypted cookie for the padded admin
    server_gencookies = remote(HOST, PORT)
    # Send the padded admin email to the server
    server_gencookies.send(padded_admin)
    # Receive the encrypted cookie for the padded admin
    encrpyted_cookie_2 = server_gencookies.recv(1024)
    # Close the connection
    server_gencookies.close()

    # Print the encrypted cookie for the padded admin
    print(encrpyted_cookie_2)

    # --------------------------

    # Combine the first part of the original cookie with the second part of the padded admin cookie
    auth_cookie = encrpyted_cookie[0:32] + encrpyted_cookie_2[16:32]
    # Connect to the server that verifies the authentication cookie
    server_test = remote(HOST, PORT+DELTA_PORT)
    # Send the combined authentication cookie to the server
    server_test.send(auth_cookie)
    # Receive the server's response
    answer = server_test.recv(1024)

    # Print the server's response
    print(answer.decode())


