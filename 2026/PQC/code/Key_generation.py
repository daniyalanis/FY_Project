'''
17 May 2026

Authors:
- Ayush Rakwal
- Baleshwar Singh
- Dipankar Dutta

About: 
- This program generates the public and private key pairs for the LWE-based encryption scheme. 
- This creates a random linear systems of equations A with secret solution s and error vector e. 
- This cryptosytem exploits the hardness of solving noisy linear equations over finite fields, which is believed to be resistant to quantum attacks. 

Usage: sage Key_generation.py <dimension> <q> <degree> <mBit>
Parameters:
- dimension (n): positive integer representing the number of variables and equations in the linear system.
- q: prime number representing the modulus.
- degree: positive integer representing the degree of the polynomial.
- mBit: positive integer representing the number of bits per chunk.

The public and private keys are saved in "public.txt" and "private.txt" respectively in plaintext format. 
The public key contains the matrix A, vector b, modulus q, degree, mBit, dimension n, and bound B. The private key contains the secret vector s.

<Sample Input/Output Sets>

Input 1:
Execution: sage Key_generation.py 7 401 1 4

Output: 
Key generated successfully

Public parameters:

A:
[104 172 232 243 330 320 297]
[352 320 191 158 207 305  23]
[223 108 188 220  59 192 304]
[123 169 169 157 256 162  22]
[351 265  56  23  16 217 137]
[280 213  38   9 209   1 119]
[ 82  81  13 391   2 171  40]

b: (37, 268, 178, 317, 287, 339, 178)

modulus: 401

dimension: 7

mBit: 4

Private parameters:

s: (1, 1, 1, 0, 1, 0, 0)


Execution duration: 0.07 seconds
'''


from sage.all import *
import sys
import time 

def validate_mBit(mBit):
    if mBit <= 0:
        raise ValueError("mBit must be a positive integer")
    if mBit <= 8:
        if 8 % mBit != 0:
            raise ValueError(
                "mBit must divide 8. Allowed values are divisors of 8: 1, 2, 4, 8."
            )
    else:
        if mBit % 8 != 0:
            raise ValueError(
                "mBit > 8 must be a multiple of 8. Allowed values are 16, 24, 32, ..."
            )


def LWE_KeyGen(n, q, degree, mBit):

    if not is_prime(q):
        raise ValueError("q must be prime.")

    validate_mBit(mBit)

    if (2**mBit) > q:
        raise ValueError("2**mBit must be smaller than q")

    step = q // 2**mBit
    min_step = 2 * n + 1

    if step < min_step:
        max_safe_mBit = floor(log(q // min_step, 2))
        raise ValueError(
            f"mBit={mBit} too large for dimension={n}, q={q}: "
            f"q//2**mBit must be >= 2*dimension+1. "
            f"Try valid smaller mBit or larger q or smaller dimension."
        )

    B = step // (2 * n + 1)
    s = vector(ZZ, [randint(0, B) for _ in range(n)])
    e = vector(ZZ, [randint(0, B) for _ in range(n)])
    A = random_matrix(GF(q), n, n, sparse=False)
    b = A * s + e

    # store bits_per_chunk for encryptor/decryptor to use
    public_params = {
        "A":    [list(map(int, row)) for row in A],
        "b":    [int(x) for x in b],
        "q":    int(q),
        "degree": int(degree),
        "mBit": int(mBit),
        "n":  int(n),
        "B":    int(B)
    }

    #private_params = {"s": [int(x) for x in s]}

    with open("public.txt", 'w') as f:
        f.write("A:\n")
        for row in A:
            row_str = "[" + " ".join(str(int(x)) for x in row) + "]"
            f.write(row_str + "\n")
        f.write("\n")
        f.write(f"b: {b}\n\n")
        f.write(f"modulus: {q}\n\n")
        f.write(f"degree: {degree}\n\n")
        f.write(f"dimension: {n}\n\n")
        f.write(f"mBit: {mBit}\n\n")
        f.write(f"B: {B}\n")

    with open("private.txt", 'w') as f:
        f.write(f"s: {s}\n\n")



    print("Key generated successfully\n")

    print("Public parameters:\n")

    print(f"A:\n{A}\n")

    print(f"b: {b}\n")

    print(f"modulus: {q}\n")

    print(f"dimension: {n}\n")

    print(f"mBit: {mBit}\n")

    print("Private parameters:\n")

    print(f"s: {s}\n")


def main():

    if len(sys.argv) != 5:
        print("Usage: sage Key_generation.py <dimension> <q> <degree> <mBit>")
        sys.exit(1)

    n = int(sys.argv[1])
    q = int(sys.argv[2])
    degree = int(sys.argv[3])
    mBit = int(sys.argv[4])

    try:
        start_time= time.time() 
        LWE_KeyGen(n, q, degree, mBit)
        duration= time.time()-start_time
        print(f"Execution duration: {duration:.2f} seconds")

    except Exception as e:
        print("Error:", e)


if __name__ == '__main__':
    main()
