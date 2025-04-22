import requests
from Crypto.Util.number import long_to_bytes, bytes_to_long

def exploit():
    # Step 1: Login with admin=1 to set admin_expire_date in the session
    s = requests.Session()
    login_url = "http://130.192.5.212:6522/login"
    response = s.get(login_url, params={"username": "a", "admin": 1})
    data = response.json()
    nonce = data['nonce']
    ciphertext = data['cookie']
    
    # Convert ciphertext to bytes for manipulation
    ct_bytes = long_to_bytes(ciphertext)
    
    # Step 2: Bit-flip to change admin=1 (if needed) and adjust expires
    # Assuming the admin bit is at the end of the cookie
    # Flipping the last bit from '1' to '1' (no change here, adjust based on actual case)
    # Modify the expires field: increase by 6 days (example)
    # This requires knowing the position of the expires field in the ciphertext
    # The following is a conceptual example
    
    # Convert to bytearray for mutation
    modified_ct = bytearray(ct_bytes)
    # Example: Adding 6 days to expires (6*86400=518400)
    # This part requires precise calculation and knowledge of the expires field's position
    # For demonstration, we assume the expires value starts at position 17 (adjust as needed)
    # This is a placeholder and may need adjustment based on actual cookie structure
    for i in range(17, 27):
        modified_ct[i] ^= 0x30  # Example XOR, adjust based on required delta
    
    # Convert back to long
    modified_ciphertext = bytes_to_long(modified_ct)
    
    # Step 3: Request the flag with the modified cookie
    flag_url = "http://130.192.5.212:6522/flag"
    response = s.get(flag_url, params={"nonce": nonce, "cookie": modified_ciphertext})
    print(response.text)

if __name__ == "__main__":
    exploit()