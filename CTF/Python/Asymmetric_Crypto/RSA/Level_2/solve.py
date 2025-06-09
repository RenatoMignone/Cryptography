# FLAG: CRYPTO25{b697e692-401f-4070-9f1f-c9dc2e97a7e9}

# ─── Attack ──────────────────────────────────────────────────────────────────────
# Attack Type: Fermat's Factorization when two prime factors are close together.
# This is classified as a mathematical attack because it exploits
# the weakness in RSA when the two prime factors p and q are close together.
# Fermat's factorization method is highly efficient when the difference
# between primes is small, as it can express n as a difference of squares.

# ─── Steps ──────────────────────────────────────────────────────────────────────
#   1. Apply Fermat's factorization to find primes p and q from modulus n.
#   2. Compute Euler's totient function φ(n) = (p-1)(q-1).
#   3. Calculate the private exponent d = e⁻¹ mod φ(n).
#   4. Decrypt the ciphertext using m = c^d mod n.
#   5. Convert the decrypted integer to bytes to reveal the flag.

# ─── Challenge Output ───────────────────────────────────────────────────────────
# 6050935527551872879286435303438132320371235206522153386309454075563003574208085513601683088
# 7120470658395455751858380183285852786807229077435165810022519265154399424311072791755790585
# 5449216994747799961986108537666770882091564578593017553132465980355772937998532560659790743
# 43370064111263698164125580000165237

# 44695558076372490838321125335259117268430036823123326565653896322404966549742986308988778274
# 3887213458112558013056583871799787369248224403827301145981699892812102669728743876579892108
# 7592195670564074051481908954633943193400111999830999228019660067218011621996625700376487167
# 0107271245284636072817194316693323

from Crypto.Util.number import long_to_bytes
import math

def fermat_factor(n):
    """
    Fermat's factorization method for finding factors when they are close together.
    Works by finding a and b such that n = a² - b² = (a-b)(a+b) = pq.
    """
    a = math.isqrt(n) + 1
    while True:
        b_squared = a * a - n
        b = math.isqrt(b_squared)
        if b * b == b_squared:
            return (a - b, a + b)
        a += 1

# ─── Given Values ────────────────────────────────────────────────────────────────
n = 60509355275518728792864353034381323203712352065221533863094540755630035742080855136016830887120470658395455751858380183285852786807229077435165810022519265154399424311072791755790585544921699474779996198610853766677088209156457859301755313246598035577293799853256065979074343370064111263698164125580000165237
c = 44695558076372490838321125335259117268430036823123326565653896322404966549742986308988778274388721345811255801305658387179978736924822440382730114598169989281210266972874387657989210875921956705640740514819089546339431934001119998309992280196600672180116219966257003764871670107271245284636072817194316693323
e = 65537

# ─── Step 1: Factor n using Fermat's method ─────────────────────────────────────
p, q = fermat_factor(n)

# ─── Step 2: Compute Euler's totient function ──────────────────────────────────
phi = (p - 1) * (q - 1)

# ─── Step 3: Compute private exponent d ─────────────────────────────────────────
d = pow(e, -1, phi)

# ─── Step 4: Decrypt the ciphertext ─────────────────────────────────────────────
m = pow(c, d, n)

# ─── Step 5: Convert to bytes and print the flag ───────────────────────────────
flag = long_to_bytes(m).decode()
print(flag)