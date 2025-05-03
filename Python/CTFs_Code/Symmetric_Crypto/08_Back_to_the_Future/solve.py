# You may have to make different guesses if you want to go in the past, 
# but if you understood the code, they would not be too much!

# HINT: have a look at the Python requests library, don't be scared by the sessions.

# HINT2: pay 80 points... if you think yoou have the solution but are encountering 
# some problems when executing the exploit...

# http://130.192.5.212:6522

#FLAG: CRYPTO25{90c01f7e-8cb7-408b-82b4-07e8e7c72d12}

import requests
from Crypto.Util.number import long_to_bytes, bytes_to_long
import time

URL = "http://130.192.5.212:6522"

def str_to_cookie_bytes(cookie_str):
    return cookie_str.encode()

def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes([x ^ y for x, y in zip(a, b)])

# Permette di mantenere una sessione HTTP persistente tra più richieste.
# Senza questa riga: ogni chiamata HTTP userebbe una sessione diversa --> il server genererebbe una nuova chiave ChaCha20 ad ogni richiesta.
# --> mantiene la stessa sessione tra chiamata a /login e /flag
# --> fa si che la chiave ChaCha20 salvata sul server non cambi
# --> permette di usare il keystream recuperato su un cookie cifrato e inviarlo nella stessa sessione, così che il server possa decifrarlo correttamente.
# Serve per mantenere lo stato della sessione e non perdere i dati session['admin_expire_date'] e session['key'], che rimangono fissi per tutta la sessione.
session = requests.Session()

# 1. Login iniziale
def initial_login():
    params = {
        "username": "admin",
        "admin": "1"
    }
    r = session.get(f"{URL}/login", params=params)
    data = r.json()

    nonce = long_to_bytes(data['nonce'])
    ciphertext = long_to_bytes(data['cookie'])

    # ricostruzione del plaintext atteso --> P
    expires_timestamp = int(time.time()) + 30 * 86400
    plaintext = f"username=admin&expires={expires_timestamp}&admin=1"
    plaintext_bytes = str_to_cookie_bytes(plaintext)

    # ricava keystream: K = P ⊕ C
    keystream = xor_bytes(plaintext_bytes, ciphertext)

    print(f"[+] Login completato. Keystream ricavato.\n    plaintext: {plaintext}")

    return nonce, keystream

# 2. Forzatura di cookie con timestamp ipotizzati
def forge_and_check(nonce, keystream):
    now = int(time.time())

    # Nota: in get_flag() osserva questa riga:
    # abs(int(token["expires"]) - session['admin_expire_date'])
    # sostituendo e semplificando ottieni: 
    # 289 gg < 30 gg + randint(10, 259) gg < 300 gg
    # Io voglio forzare expire_date in modo che non siano più 30 gg, ma lo stesso valore randomico scelto da session['admin_expire_date'], in modo da poterlo semplificare.
    # Essendo il tutto randomico, devo fare un bruteforce per trovare il valore corretto.
    # Inoltre aggiungo 295 gg 
    # Così, nel controllo di get_flag() ottengo:
    # 290 gg < oggi - randomico + 295 gg - oggi + randomico < 300 gg --> 290 gg < 295 gg < 300 gg

    # --> Mando il cookie al server finché uno supera il controllo e mi restituisce la flag.

    for guessed_days_ago in range(10, 260):
        guessed_admin_expire = now - guessed_days_ago * 86400
        forged_expires = guessed_admin_expire + 295 * 86400

        cookie_str = f"username=admin&expires={forged_expires}&admin=1"
        cookie_bytes = str_to_cookie_bytes(cookie_str)

        # xor con keystream --> ottengo nuovo ciphertext con expires forzato
        forged_ciphertext = xor_bytes(cookie_bytes, keystream)

        # invio alla route /flag
        params = {
            "nonce": str(bytes_to_long(nonce)),
            "cookie": str(bytes_to_long(forged_ciphertext))
        }
        r = session.get(f"{URL}/flag", params=params)
        print(f"[{guessed_days_ago}] Tentativo con expires={forged_expires} → {r.text}")

        if "flag" in r.text.lower():
            print("\n FLAG TROVATA")
            print(r.text)
            break

# 3. Main
def main():
    nonce, keystream = initial_login()
    forge_and_check(nonce, keystream)

if __name__ == "__main__":
    main()