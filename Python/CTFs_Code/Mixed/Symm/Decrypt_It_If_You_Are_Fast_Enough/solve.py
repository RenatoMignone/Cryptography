#FLAG: CRYPTO25{23ae15cf-c924-416c-b44d-fde94f18cc0c}

from pwn import *
from Crypto.Cipher import ChaCha20
from Crypto.Util.number import long_to_bytes
import time

HOST = "130.192.5.212"
PORT = 6562

def get_ciphertexts(io, known_plain):
    io.sendlineafter(b"Want to encrypt? (y/n/f)", b"y")
    io.sendlineafter(b"> ", known_plain)
    ct_known = bytes.fromhex(io.recvline().strip().decode())

    io.sendlineafter(b"Want to encrypt something else? (y/n/f)", b"f")
    ct_flag = bytes.fromhex(io.recvline().strip().decode())
    return ct_known, ct_flag

def brute_nonce_and_recover_flag(ct_known, pt_known, ct_flag, time_window=40):
    now = int(time.time())
    for t in range(now - time_window, now + time_window + 1):
        random.seed(t)
        nonce = long_to_bytes(random.getrandbits(12*8))
        # Try all possible nonces in the window
        try:
            cipher = ChaCha20.new(key=b"\x00"*32, nonce=nonce)
            # We don't know the key, but the keystream is the same for both encryptions
            # So we can recover the keystream from known plaintext/ciphertext
            # and use it to decrypt the flag ciphertext
            # But we need the key, so this approach doesn't work directly.
            # Instead, since the key is fixed, but unknown, and the nonce is reused,
            # the keystream is the same for both encryptions.
            # So: keystream = ct_known ^ pt_known
            # flag = ct_flag ^ keystream
            keystream = bytes([a ^ b for a, b in zip(ct_known, pt_known)])
            flag = bytes([a ^ b for a, b in zip(ct_flag, keystream)])
            # Print partial flag for debugging
            try:
                flag_str = flag.decode(errors="ignore")
            except Exception:
                flag_str = repr(flag)
            if b"flag" in flag or b"FLAG" in flag or b"{" in flag:
                return flag_str
            # Print partial result for debugging
            if flag_str.startswith("CRYPTO") or "{" in flag_str:
                print("Partial flag candidate:", flag_str)
        except Exception:
            continue
    return None

def main():
    # Use a longer known plaintext to match likely flag length
    known_plain = b"A"*48
    for attempt in range(30):
        io = remote(HOST, PORT)
        ct_known, ct_flag = get_ciphertexts(io, known_plain)
        io.close()
        flag = brute_nonce_and_recover_flag(ct_known, known_plain, ct_flag)
        if flag:
            print("Flag:", flag)
            break
        else:
            print(f"Attempt {attempt+1}: Flag not found. Retrying...")
        time.sleep(0.3)
    else:
        print("Flag not found after multiple attempts. Try increasing the time window or attempts.")

if __name__ == "__main__":
    main()
