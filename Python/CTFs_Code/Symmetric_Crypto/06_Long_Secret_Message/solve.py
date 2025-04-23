import os
import urllib.request
import re

MANIFESTO_URL = "https://www.gutenberg.org/cache/epub/46996/pg46996.txt"
MANIFESTO_LOCAL = "hacker-manifesto.txt"

if not os.path.exists(MANIFESTO_LOCAL):
    print("Downloading hacker-manifesto.txt ...")
    urllib.request.urlretrieve(MANIFESTO_URL, MANIFESTO_LOCAL)

with open(MANIFESTO_LOCAL, encoding="utf-8", errors="ignore") as f:
    orig_lines = f.readlines()

with open("hacker-manifesto.enc") as f:
    enc_lines = [bytes.fromhex(line.strip()) for line in f]

flag_regex = re.compile(r"CRYPTO25\{[0-9a-fA-F\-]{36}\}")

# Try keystreams from each known line
for ks_idx in range(min(len(orig_lines), len(enc_lines))):
    plain = orig_lines[ks_idx].encode()
    enc = enc_lines[ks_idx]
    keystream = bytes([c ^ p for c, p in zip(enc, plain[:len(enc)])])
    print(f"\n\n\n--- Trying keystream from line {ks_idx} ---")
    for i, enc2 in enumerate(enc_lines):
        decrypted = bytes([c ^ k for c, k in zip(enc2, keystream)])
        line = decrypted.decode(errors="replace")
        if flag_regex.search(line):
            print(f"Flag found using keystream from line {ks_idx} on encrypted line {i}: {flag_regex.search(line).group()}")
        # Optionally print all lines:
        print(line, end="")