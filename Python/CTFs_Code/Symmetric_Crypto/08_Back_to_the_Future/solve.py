#################################################################################
# You may have to make different guesses if you want to go in the past, 
# but if you understood the code, they would not be too much!

# HINT: have a look at the Python requests library, don't be scared by the sessions.

# HINT2: pay 80 points... if you think yoou have the solution but are encountering 
# some problems when executing the exploit...

# http://130.192.5.212:6522

#################################################################################
#FLAG: CRYPTO25{90c01f7e-8cb7-408b-82b4-07e8e7c72d12}
#################################################################################

#################################################################################
# Attack: Key Stream Reuse
#################################################################################


import requests
from Crypto.Util.number import long_to_bytes, bytes_to_long
import time

#-----------------------------------------------------------------
URL = "http://130.192.5.212:6522"
# Create a session to persist cookies and session data across requests
session = requests.Session()

#-----------------------------------------------------------------
def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

#-----------------------------------------------------------------
def login():

    # Prepare login parameters to request admin privileges
    params = {
        "username": "admin",
        "admin": "1"
    }

    # Send login request and receive the encrypted cookie and nonce
    r = session.get(f"{URL}/login", params=params).json()
    
    # Convert the received nonce from integer to bytes
    nonce = long_to_bytes(r['nonce'])
    # Convert the received ciphertext from integer to bytes
    ct = long_to_bytes(r['cookie'])

    # Compute the expected 'expires' field as the server would set it
    expires = int(time.time()) + 30 * 86400

    # Build the known plaintext cookie string as defined by the server
    pt = f"username=admin&expires={expires}&admin=1".encode()

    # Since we have send the request with the plaintext, and we got the ciphertext, we XOR and get the keystream
    return nonce, xor_bytes(pt, ct)


#-----------------------------------------------------------------
def flag(nonce, keystream):
    # Get the current time to compute possible admin_expire dates
    now = int(time.time())

    # Brute-force possible admin_expire values within the range defined by the server
    for days_ago in range(10, 260):
        # Compute a possible admin_expire date in the past, based on the guess
        admin_expire = now - days_ago * 86400
        
        # Forge an 'expires' value that will pass the server's time check
        # The value 295 is because it is in the middle between 290 and 300 days
        forged_expires = admin_expire + 295 * 86400

        # Build the forged plaintext cookie with admin privileges and forged expiry
        forged_pt = f"username=admin&expires={forged_expires}&admin=1".encode()

        # Encrypt the forged plaintext using the recovered keystream
        forged_ct = xor_bytes(forged_pt, keystream)

        # Prepare parameters for the /flag endpoint
        params = {
            "nonce": str(bytes_to_long(nonce)),
            "cookie": str(bytes_to_long(forged_ct))
        }

        # Send the forged cookie to the server to try to retrieve the flag
        resp = session.get(f"{URL}/flag", params=params).text

        # Print the forged expiry date and the server's response for debugging
        print(f"[{days_ago}] expires={forged_expires} -> {resp}")
        
        # If the flag is found in the response, print and stop
        if "flag" in resp.lower():
            print("\nFLAG:", resp)
            break


#-----------------------------------------------------------------
def main():
    # Recover the keystream by logging in as admin and knowing the plaintext
    nonce, keystream = login()
    # Attempt to forge cookies and retrieve the flag
    flag(nonce, keystream)


#-----------------------------------------------------------------
if __name__ == "__main__":
    main()