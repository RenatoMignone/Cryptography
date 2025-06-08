# FLAG: CRYPTO25{X5a.7}

# ─── Attack ──────────────────────────────────────────────────────────────────────
# This is classified as a mathematical attack because it exploits
# the factorization weakness of RSA when small primes are used.
# When n can be factored into its prime components p and q,
# the private key can be reconstructed and the ciphertext decrypted.

# ─── Steps ──────────────────────────────────────────────────────────────────────
#   1. Factor the modulus `n` using FactorDB to obtain primes `p` and `q`.
#   2. Compute Euler's totient function `φ(n) = (p-1)(q-1)`.
#   3. Calculate the private exponent `d = e⁻¹ mod φ(n)`.
#   4. Decrypt the ciphertext using `m = c^d mod n`.
#   5. Convert the decrypted integer to bytes to reveal the flag.

from Crypto.Util.number import long_to_bytes
from factordb.factordb import FactorDB

# ─── Given Values ────────────────────────────────────────────────────────────────
n = 176278749487742942508568320862050211633
c = 46228309104141229075992607107041922411
e = 65537

# ─── Step 1: Factor n via FactorDB ──────────────────────────────────────────────
f = FactorDB(str(n))
f.connect()
# get_factor_list() returns a list of prime factors (with multiplicity if needed)
factors = f.get_factor_list()
if len(factors) != 2:
    raise ValueError(f"Expected 2 primes, got {factors!r}")
p, q = factors

# ─── Step 2: Compute Euler's totient function ──────────────────────────────────
phi = (p - 1) * (q - 1)

# ─── Step 3: Compute private exponent d ─────────────────────────────────────────
d = pow(e, -1, phi)

# ─── Step 4: Decrypt the ciphertext ─────────────────────────────────────────────
m = pow(c, d, n)

# ─── Step 5: Convert to bytes and print the flag ───────────────────────────────
flag = long_to_bytes(m)
print(f"Flag: {flag.decode()}")