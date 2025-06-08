from Crypto.Cipher import ChaCha20
from Crypto.Random import get_random_bytes
from Crypto.Util.number import long_to_bytes, bytes_to_long
import time
from random import randint
from secret import flag
from flask import Flask, session, jsonify, request
from flask_session import Session

app = Flask(__name__)
app.secret_key = get_random_bytes(16).hex()
app.config['SESSION_TYPE'] = 'filesystem'
sess = Session()
sess.init_app(app)


# Function to create a new ChaCha20 cipher with random key and nonce
def make_cipher():
    # Generate a random 32-byte key
    key = get_random_bytes(32)
    # Generate a random 12-byte nonce
    nonce = get_random_bytes(12)
    # Create a new ChaCha20 cipher object
    cipher = ChaCha20.new(key=key, nonce=nonce)
    # Return the nonce, key, and cipher object
    return nonce, key, cipher


# Function to sanitize a string field by removing or replacing special characters
def sanitize_field(field: str):
    # Replace or remove various special characters from the input string
    return field \
        .replace(" ", "_") \
        .replace("/", "_") \
        .replace("&", "") \
        .replace(":", "") \
        .replace(";", "") \
        .replace("<", "") \
        .replace(">", "") \
        .replace('"', "") \
        .replace("'", "") \
        .replace("(", "") \
        .replace(")", "") \
        .replace("[", "") \
        .replace("]", "") \
        .replace("{", "") \
        .replace("}", "") \
        .replace("=", "")


# Function to parse a cookie string into a dictionary
def parse_cookie(cookie: str) -> dict:
    parsed = {}
    # Split the cookie string by '&' to get individual fields
    for field in cookie.split("&"):
        # Split each field by '=' to get key-value pairs
        key, value = field.split("=")
        # Sanitize the key and value
        key = sanitize_field(key)
        value = sanitize_field(value)
        # Add the key-value pair to the parsed dictionary
        parsed[key] = value

    return parsed


# Route for user login
@app.route("/login", methods=["GET"])
def login():
    # Get the username and admin status from the request arguments
    username = request.args.get("username")
    admin = int(request.args.get("admin"))

    # Create a new cipher for encryption
    nonce, key, cipher = make_cipher()
    # Store the encryption key in the session
    session['key'] = key

    # Sanitize the username to remove special characters
    username = sanitize_field(username)

    # Set admin status and expiration date in the session
    if admin != 1:
        admin = 0
    else:
        # The admin expire date is based on the current time minus a random number of days from 10 to 259
        session['admin_expire_date'] = int(time.time()) - randint(10, 259) * 24 * 60 * 60

    # Set the expiration date to 30 days from now
    expire_date = int(time.time()) + 30 * 24 * 60 * 60

    # Create a cookie string with username, expiration date, and admin status
    cookie = f"username={username}&expires={expire_date}&admin={admin}"

    # Return the nonce and encrypted cookie as a JSON response
    return jsonify({
        "nonce": bytes_to_long(nonce),
        "cookie": bytes_to_long(cipher.encrypt(cookie.encode()))
    })


# Route to access the flag (admin only)
@app.route("/flag", methods=["GET"])
def get_flag():
    # Get the nonce and cookie from the request arguments
    nonce = int(request.args.get("nonce"))
    cookie = int(request.args.get("cookie"))

    # Create a new cipher for decryption using the stored key and nonce
    cipher = ChaCha20.new(nonce=long_to_bytes(nonce), key=session['key'])

    try:
        # Decrypt the cookie using the cipher
        dec_cookie = cipher.decrypt(long_to_bytes(cookie)).decode()
        # Parse the decrypted cookie into a token dictionary
        token = parse_cookie(dec_cookie)

        # Check if the user is an admin
        if int(token["admin"]) != 1:
            return "You are not an admin!"

        # Check if the admin session is still valid
        # If the token's 'expires' field  minus the session's admin expiration date is between 290 and 300 days,
        # then the session is valid and the flag can be returned
        if 290 * 24 * 60 * 60 < abs(int(token["expires"]) - session['admin_expire_date']) < 300 * 24 * 60 * 60:
            return f"OK! Your flag: {flag}"
        else:
            return "You have expired!"
    except:
        return "Something didn't work :C"
