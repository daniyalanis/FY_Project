#!/usr/bin/python3   

"""
"" 20th November 2026 ::: Daniyal Anis, Sarbo Sarcar, Srijani Roy  
"" 
"" Usage : python3 keygen.py <parameter_set>
""
"" <parameter_set> : ML-KEM parameter set. Allowed values are 512, 768 and 1024.
""
"" This Program generates an ML-KEM (FIPS 203) key pair for the selected
"" parameter set. It implements ML-KEM.KeyGen, which
"" calls ML-KEM.KeyGen_internal, which in turn calls
"" K-PKE.KeyGen.
""
"" The Program writes the encapsulation key to ek.bin and the decapsulation
"" key to dk.bin in the current working directory as raw bytes. Keep dk.bin
"" private. The shared secret is not produced during key generation; it is
"" produced later by encapsulation.
""
"" Sample Input/Output Sets                 
""
"" Only 512, 768 and 1024 are valid, so the sets repeat; every run draws fresh
"" random seeds.
""
"" INPUT 1:-
"" Execution: python3 keygen.py 512
"" OUTPUT 1:-
"" ML-KEM-512 key pair generated.
"" ek.bin : 800 bytes
"" dk.bin : 1632 bytes
"" Time Taken = 0.0028 Sec (Macbook Air M3)
""
"" INPUT 2:-
"" Execution: python3 keygen.py 768
"" OUTPUT 2:-
"" ML-KEM-768 key pair generated.
"" ek.bin : 1184 bytes
"" dk.bin : 2400 bytes
"" Time Taken = 0.0036 Sec (Macbook Air M3)
""
"" INPUT 3:-
"" Execution: python3 keygen.py 1024
"" OUTPUT 3:-
"" ML-KEM-1024 key pair generated.
"" ek.bin : 1568 bytes
"" dk.bin : 3168 bytes
"" Time Taken = 0.0054 Sec (Macbook Air M3)
""
"" INPUT 4:-
"" Execution: python3 keygen.py 512
"" OUTPUT 4:-
"" ML-KEM-512 key pair generated.
"" ek.bin : 800 bytes
"" dk.bin : 1632 bytes
"" Time Taken = 0.0024 Sec (Macbook Air M3)
""
"" INPUT 5:-
"" Execution: python3 keygen.py 768
"" OUTPUT 5:-
"" ML-KEM-768 key pair generated.
"" ek.bin : 1184 bytes
"" dk.bin : 2400 bytes
"" Time Taken = 0.0036 Sec (Macbook Air M3)
""
"" INPUT 6:-
"" Execution: python3 keygen.py 1024
"" OUTPUT 6:-
"" ML-KEM-1024 key pair generated.
"" ek.bin : 1568 bytes
"" dk.bin : 3168 bytes
"" Time Taken = 0.0053 Sec (Macbook Air M3)
""
"" INPUT 7:-
"" Execution: python3 keygen.py 512
"" OUTPUT 7:-
"" ML-KEM-512 key pair generated.
"" ek.bin : 800 bytes
"" dk.bin : 1632 bytes
"" Time Taken = 0.0026 Sec (Macbook Air M3)
""
"" INPUT 8:-
"" Execution: python3 keygen.py 768
"" OUTPUT 8:-
"" ML-KEM-768 key pair generated.
"" ek.bin : 1184 bytes
"" dk.bin : 2400 bytes
"" Time Taken = 0.0036 Sec (Macbook Air M3)
""
"" INPUT 9:-
"" Execution: python3 keygen.py 1024
"" OUTPUT 9:-
"" ML-KEM-1024 key pair generated.
"" ek.bin : 1568 bytes
"" dk.bin : 3168 bytes
"" Time Taken = 0.0053 Sec (Macbook Air M3)
""
"" INPUT 10:-
"" Execution: python3 keygen.py 512
"" OUTPUT 10:-
"" ML-KEM-512 key pair generated.
"" ek.bin : 800 bytes
"" dk.bin : 1632 bytes
"" Time Taken = 0.0024 Sec (Macbook Air M3)
""
"" Input Details
"" - parameter_set : 512, 768 or 1024.
"" - Randomness : two fresh 32-byte seeds d and z from the operating-system RBG.
""
"" Output Details
"" - ek.bin : raw encapsulation key, 384*k + 32 bytes.
"" - dk.bin : raw decapsulation key, 768*k + 96 bytes.
""
"" Time Taken ::: System Details
"" - The elapsed time is printed at run time; the values above were measured on a Macbook Air M3 with python3 (CPython 3.9.6).
""
"""

import sys
import hashlib
import secrets
import time

"""
"" The following code is for Single Stepping Debugging Process.
"" 
"" import pdb
""
"" pdb.set_trace()
""
"" Important pdb commands:-
"" n: Step to the next line of code.
"" s: Step into a function call.
"" c: Continue execution until the next breakpoint or the end of the program.
"" q: Quit the debugger.
""
"""

# ML-KEM global constants
N = 256
Q = 3329
ZETA = 17

# Approved parameter sets
PARAMETER_SETS = {
	512:  {"k": 2, "eta1": 3, "eta2": 2, "du": 10, "dv": 4},
	768:  {"k": 3, "eta1": 2, "eta2": 2, "du": 10, "dv": 4},
	1024: {"k": 4, "eta1": 2, "eta2": 2, "du": 11, "dv": 5},
}

USAGE="Usage : python3 keygen.py <parameter_set>"


# ---------------------------------------------------------------------------
# Auxiliary functions
# ---------------------------------------------------------------------------

def H(ByteString):
	# SHA3-256 hash.
	return hashlib.sha3_256(ByteString).digest()


def G(ByteString):
	# SHA3-512 hash; the 64-byte digest is split into two 32-byte seeds.
	Digest = hashlib.sha3_512(ByteString).digest()
	return Digest[:32], Digest[32:]


def PRF(Seed, Nonce, Eta):
	# PRF_eta(s, b) = SHAKE256(s || b, 64*eta).
	return hashlib.shake_256(Seed + bytes([Nonce])).digest(64 * Eta)


def BitRev7(Value):
	# Reverse the seven low-order bits of Value.
	Result = 0
	for i in range(7):
		Result = (Result << 1) | ((Value >> i) & 1)
	return Result


# Precomputed twiddle factors.
ZETAS = [pow(ZETA, BitRev7(i), Q) for i in range(128)]
GAMMAS = [pow(ZETA, 2 * BitRev7(i) + 1, Q) for i in range(128)]


def BytesToBits(ByteString):
	# Little-endian bit expansion of a byte string.
	Bits = []
	for Byte in ByteString:
		for j in range(8):
			Bits.append((Byte >> j) & 1)
	return Bits


def SampleNTT(Seed, Index1, Index2):
	# Rejection sampling of one NTT-domain polynomial.
	# XOF(rho, i, j) = SHAKE128(rho || byte(i) || byte(j)) is an XOF stream;
	# more bytes are requested if rejection sampling consumes the current batch.
	OutputLength = 3 * N
	while True:
		Stream = hashlib.shake_128(Seed + bytes([Index1, Index2])).digest(OutputLength)
		Coefficients = []
		Offset = 0
		while ((Offset + 3 <= len(Stream)) and (len(Coefficients) < N)):
			C0 = Stream[Offset]
			C1 = Stream[Offset + 1]
			C2 = Stream[Offset + 2]
			D1 = C0 + 256 * (C1 % 16)
			D2 = (C1 // 16) + 16 * C2
			if D1 < Q:
				Coefficients.append(D1)
			if ((D2 < Q) and (len(Coefficients) < N)):
				Coefficients.append(D2)
			Offset += 3
		if len(Coefficients) >= N:
			return Coefficients[:N]
		OutputLength *= 2


def SamplePolyCBD(ByteString, Eta):
	# Centered binomial distribution.
	Bits = BytesToBits(ByteString)
	Coefficients = [0] * N
	for i in range(N):
		X = 0
		Y = 0
		Base = 2 * i * Eta
		for j in range(Eta):
			X += Bits[Base + j]
			Y += Bits[Base + Eta + j]
		Coefficients[i] = (X - Y) % Q
	return Coefficients


# ---------------------------------------------------------------------------
# NTT and NTT-domain arithmetic.
# ---------------------------------------------------------------------------

def NTT(Coefficients):
	# Forward NTT.
	Result = list(Coefficients)
	Index = 1
	Length = 128
	while Length >= 2:
		Start = 0
		while Start < N:
			Twiddle = ZETAS[Index]
			Index += 1
			for j in range(Start, Start + Length):
				T = (Twiddle * Result[j + Length]) % Q
				Result[j + Length] = (Result[j] - T) % Q
				Result[j] = (Result[j] + T) % Q
			Start += 2 * Length
		Length //= 2
	return Result


def BaseCaseMultiply(A0, A1, B0, B1, Gamma):
	# Product of two degree-one polynomials modulo X^2 - Gamma.
	C0 = (A0 * B0 + A1 * B1 * Gamma) % Q
	C1 = (A0 * B1 + A1 * B0) % Q
	return C0, C1


def MultiplyNTTs(F, G_):
	# Multiplication in the NTT domain.
	# This is NOT coefficient-wise multiplication: each adjacent pair is a
	# degree-one polynomial modulo X^2 - GAMMAS[i].
	Result = [0] * N
	for i in range(128):
		C0, C1 = BaseCaseMultiply(F[2 * i], F[2 * i + 1], G_[2 * i], G_[2 * i + 1], GAMMAS[i])
		Result[2 * i] = C0
		Result[2 * i + 1] = C1
	return Result


# ---------------------------------------------------------------------------
# Encoding
# ---------------------------------------------------------------------------

def ByteEncode12(Coefficients):
	# 12-bit little-endian encoding of 256 coefficients into 384 bytes
	# (FIPS 203, Algorithm 5, with d = 12).
	Result = bytearray()
	Accumulator = 0
	BitCount = 0
	for Coefficient in Coefficients:
		Accumulator |= (Coefficient % Q) << BitCount
		BitCount += 12
		while BitCount >= 8:
			Result.append(Accumulator & 0xFF)
			Accumulator >>= 8
			BitCount -= 8
	if BitCount > 0:
		Result.append(Accumulator & 0xFF)
	return bytes(Result)


# ---------------------------------------------------------------------------
# ML-KEM key generation
# ---------------------------------------------------------------------------

def ML_KEM_KeyGen(ParameterSet, D=None, Z=None):
	# ML-KEM.KeyGen: draw d and z, then run
	# ML-KEM.KeyGen_internal, which calls K-PKE.KeyGen.
	Params = PARAMETER_SETS[ParameterSet]
	k = Params["k"]
	Eta1 = Params["eta1"]

	# Fresh 32-byte seeds from the operating-system RBG,
	# unless supplied by the caller for deterministic testing.
	if D is None:
		D = secrets.token_bytes(32)
	if Z is None:
		Z = secrets.token_bytes(32)

	# (rho, sigma) = G(d || byte(k)).
	Rho, Sigma = G(D + bytes([k]))

	# A_hat[i][j] = SampleNTT(XOF(rho, j, i)); column index first.
	A_hat = [[None] * k for _ in range(k)]
	for i in range(k):
		for j in range(k):
			A_hat[i][j] = SampleNTT(Rho, j, i)

	# Sample the secret vector s and the error vector e with nonces 0..2k-1.
	S = []
	E = []
	Nonce = 0
	for i in range(k):
		S.append(SamplePolyCBD(PRF(Sigma, Nonce, Eta1), Eta1))
		Nonce += 1
	for i in range(k):
		E.append(SamplePolyCBD(PRF(Sigma, Nonce, Eta1), Eta1))
		Nonce += 1

	# NTT of s and e.
	S_hat = [NTT(Poly) for Poly in S]
	E_hat = [NTT(Poly) for Poly in E]

	# t_hat[i] = e_hat[i] + sum_j MultiplyNTTs(A_hat[i][j], s_hat[j]).
	T_hat = []
	for i in range(k):
		Accumulator = list(E_hat[i])
		for j in range(k):
			Product = MultiplyNTTs(A_hat[i][j], S_hat[j])
			for x in range(N):
				Accumulator[x] = (Accumulator[x] + Product[x]) % Q
		T_hat.append(Accumulator)

	# ek = ByteEncode12(t_hat) || rho.
	Ek = bytearray()
	for Poly in T_hat:
		Ek += ByteEncode12(Poly)
	Ek += Rho
	Ek = bytes(Ek)

	# dk = ByteEncode12(s_hat) || ek || H(ek) || z.
	Dk = bytearray()
	for Poly in S_hat:
		Dk += ByteEncode12(Poly)
	Dk += Ek + H(Ek) + Z
	Dk = bytes(Dk)

	return Ek, Dk


print("\n")

if (len(sys.argv) != 2):
	print (f"Problem with Arguments!")
	print (f"\n{USAGE}")
	exit(1)

try:
	Parameter_Set = int(sys.argv[1])
except Exception:
	print (f"Problem with Argument! parameter_set should be 512, 768 or 1024.")
	print (f"\n{USAGE}")
	exit(1)

if (Parameter_Set not in (512, 768, 1024)):
	print (f"Problem with Argument! parameter_set should be 512, 768 or 1024.")
	print (f"\n{USAGE}")
	exit(1)

try:
	Start_Time = time.time()
	Ek, Dk = ML_KEM_KeyGen(Parameter_Set)
	Duration = time.time() - Start_Time

	with open("ek.bin", "wb") as Ek_File:
		Ek_File.write(Ek)
	with open("dk.bin", "wb") as Dk_File:
		Dk_File.write(Dk)

	print(f"ML-KEM-{Parameter_Set} key pair generated.")
	print(f"ek.bin : {len(Ek)} bytes")
	print(f"dk.bin : {len(Dk)} bytes")
	print(f"Time Taken = {Duration:.4f} Sec (Macbook Air M3)")

except Exception as Error:
	print("Error:", Error)
	exit(1)

print("\n")
exit(0)

"""
"""
