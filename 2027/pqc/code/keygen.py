#!/usr/bin/python3   

"""
"" 20th November 2026 ::: Daniyal Anis, Sarbo Sarcar, Srijani Roy  
"" 
"" Usage : python3 keygen.py <parameter_set>
""
"" <parameter_set> : ML-KEM parameter set. Allowed values are 512, 768 and 1024.
""
"" This Program generates an ML-KEM (FIPS 203) key pair for the selected
"" parameter set. It implements ML-KEM.KeyGen (FIPS 203, Algorithm 19), which
"" calls ML-KEM.KeyGen_internal (Algorithm 16), which in turn calls
"" K-PKE.KeyGen (Algorithm 13).
""
"" The Program writes the encapsulation key to ek.bin and the decapsulation
"" key to dk.bin in the current working directory as raw bytes. Keep dk.bin
"" private. The shared secret is not produced during key generation; it is
"" produced later by encapsulation.
""
"" The module can also be imported without side effects; call ML_KEM_KeyGen(...)
"" from Python directly, optionally passing 32-byte d and z seeds. It also
"" exports the shared helpers used by encap.py and decap.py.
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
"" - parameter_set : 512, 768 or 1024 (no default).
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

# ML-KEM global constants (FIPS 203, Sections 2.4 and 4.3).
N = 256
Q = 3329
ZETA = 17

# Approved parameter sets (FIPS 203, Table 2).
PARAMETER_SETS = {
	512:  {"k": 2, "eta1": 3, "eta2": 2, "du": 10, "dv": 4},
	768:  {"k": 3, "eta1": 2, "eta2": 2, "du": 10, "dv": 4},
	1024: {"k": 4, "eta1": 2, "eta2": 2, "du": 11, "dv": 5},
}

USAGE="Usage : python3 keygen.py <parameter_set>"


# ---------------------------------------------------------------------------
# Auxiliary functions (FIPS 203, Section 4)
# ---------------------------------------------------------------------------

def H(ByteString):
	"""Compute H(s) = SHA3-256(s) (FIPS 203, Section 4.1).

	Args:
		ByteString: Input bytes.
	Returns:
		The 32-byte hash digest.
	"""
	# SHA3-256 hash (FIPS 203, Section 4.1).
	return hashlib.sha3_256(ByteString).digest()


def G(ByteString):
	"""Compute G(c) = SHA3-512(c) and split it into two 32-byte seeds.

	Args:
		ByteString: Input bytes (d || byte(k) in key generation, m || H(ek) in encapsulation).
	Returns:
		A pair of 32-byte values (first half, second half of the digest).
	"""
	# SHA3-512 hash; the 64-byte digest is split into two 32-byte seeds.
	Digest = hashlib.sha3_512(ByteString).digest()
	return Digest[:32], Digest[32:]


def J(ByteString):
	"""Compute J(s) = SHAKE256(s, 32) (FIPS 203, Equation 4.4).

	Args:
		ByteString: Input bytes, normally z || c on implicit rejection.
	Returns:
		A 32-byte pseudorandom value.
	"""
	# SHAKE256 with a 32-byte output (FIPS 203, Equation 4.4).
	return hashlib.shake_256(ByteString).digest(32)


def PRF(Seed, Nonce, Eta):
	"""Compute PRF_eta(s, b) = SHAKE256(s || b, 64*eta) (FIPS 203, Eq. 4.3).

	Args:
		Seed: 32-byte seed (sigma in key generation, r in encryption).
		Nonce: One-byte nonce.
		Eta: CBD parameter (2 or 3); sets the 64*eta byte output length.
	Returns:
		A byte string of length 64*Eta.
	"""
	# PRF_eta(s, b) = SHAKE256(s || b, 64*eta) (FIPS 203, Equation 4.3).
	return hashlib.shake_256(Seed + bytes([Nonce])).digest(64 * Eta)


def BitRev7(Value):
	"""Reverse the seven low-order bits of Value (FIPS 203, Section 4.3).

	Args:
		Value: Integer in the range 0..127.
	Returns:
		The 7-bit reversal of Value.
	"""
	# Reverse the seven low-order bits of Value (FIPS 203, Section 4.3).
	Result = 0
	for i in range(7):
		Result = (Result << 1) | ((Value >> i) & 1)
	return Result


# Precomputed twiddle factors (FIPS 203, Appendix A).
ZETAS = [pow(ZETA, BitRev7(i), Q) for i in range(128)]
GAMMAS = [pow(ZETA, 2 * BitRev7(i) + 1, Q) for i in range(128)]


def BytesToBits(ByteString):
	"""Expand a byte string into little-endian bits (FIPS 203, Algorithm 4).

	Args:
		ByteString: Bytes to expand.
	Returns:
		A list of 0/1 values, least-significant bit first in each byte.
	"""
	# Little-endian bit expansion of a byte string (FIPS 203, Algorithm 4).
	Bits = []
	for Byte in ByteString:
		for j in range(8):
			Bits.append((Byte >> j) & 1)
	return Bits


def SampleNTT(Seed, Index1, Index2):
	"""Rejection-sample one NTT polynomial from XOF(rho, j, i) (Algorithm 7).

	Args:
		Seed: 32-byte rho seed.
		Index1: First index byte (j, the column).
		Index2: Second index byte (i, the row).
	Returns:
		256 coefficients uniformly distributed modulo q.
	"""
	# Rejection sampling of one NTT-domain polynomial (FIPS 203, Algorithm 7).
	# XOF(rho, j, i) = SHAKE128(rho || byte(j) || byte(i)) is an XOF stream;
	# the column byte j is absorbed before the row byte i.
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
	"""Sample a polynomial from the centered binomial distribution (Algorithm 8).

	Args:
		ByteString: 64*Eta pseudorandom bytes from PRF.
		Eta: CBD parameter (2 or 3).
	Returns:
		256 coefficients reduced modulo q.
	"""
	# Centered binomial distribution (FIPS 203, Algorithm 8).
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


def SampleMatrix(Rho, k):
	"""Regenerate the k x k NTT matrix from rho (K-PKE KeyGen/Encrypt).

	Args:
		Rho: 32-byte matrix seed from the encapsulation key.
		k: Module rank (2, 3 or 4).
	Returns:
		A k x k list of NTT polynomials, with column index j before row index i.
	"""
	# k x k matrix of NTT polynomials; column index j precedes row index i.
	return [[SampleNTT(Rho, j, i) for j in range(k)] for i in range(k)]


# ---------------------------------------------------------------------------
# NTT and NTT-domain arithmetic (FIPS 203, Section 4.3)
# ---------------------------------------------------------------------------

def NTT(Coefficients):
	"""Compute the forward NTT (FIPS 203, Algorithm 9).

	Args:
		Coefficients: 256 coefficients in R_q.
	Returns:
		256 coefficients in the NTT domain T_q.
	"""
	# Forward NTT (FIPS 203, Algorithm 9).
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


def NTTInverse(Coefficients):
	"""Compute the inverse NTT with final scale 3303 (Algorithm 10).

	Args:
		Coefficients: 256 coefficients in the NTT domain T_q.
	Returns:
		256 coefficients in R_q.
	"""
	# Inverse NTT with final scale 3303 = 128^-1 mod q (FIPS 203, Algorithm 10).
	Result = list(Coefficients)
	Index = 127
	Length = 2
	while Length <= 128:
		Start = 0
		while Start < N:
			Twiddle = ZETAS[Index]
			Index -= 1
			for j in range(Start, Start + Length):
				T = Result[j]
				Result[j] = (T + Result[j + Length]) % Q
				Result[j + Length] = (Twiddle * (Result[j + Length] - T)) % Q
			Start += 2 * Length
		Length *= 2
	return [(3303 * Value) % Q for Value in Result]


def BaseCaseMultiply(A0, A1, B0, B1, Gamma):
	"""Multiply two degree-one polynomials modulo X^2 - Gamma (Algorithm 12).

	Args:
		A0, A1: Coefficients of the first polynomial.
		B0, B1: Coefficients of the second polynomial.
		Gamma: Quadratic modulus coefficient.
	Returns:
		The two coefficients (c0, c1) of the product, modulo q.
	"""
	# Product of two degree-one polynomials modulo X^2 - Gamma (Algorithm 12).
	C0 = (A0 * B0 + A1 * B1 * Gamma) % Q
	C1 = (A0 * B1 + A1 * B0) % Q
	return C0, C1


def MultiplyNTTs(F, G_):
	"""Multiply two NTT representations in T_q (FIPS 203, Algorithm 11).

	Args:
		F: First 256-coefficient NTT polynomial.
		G_: Second 256-coefficient NTT polynomial.
	Returns:
		The 256-coefficient product in the NTT domain.
	"""
	# Multiplication in the NTT domain (FIPS 203, Algorithm 11).
	# This is NOT coefficient-wise multiplication: each adjacent pair is a
	# degree-one polynomial modulo X^2 - GAMMAS[i].
	Result = [0] * N
	for i in range(128):
		C0, C1 = BaseCaseMultiply(F[2 * i], F[2 * i + 1], G_[2 * i], G_[2 * i + 1], GAMMAS[i])
		Result[2 * i] = C0
		Result[2 * i + 1] = C1
	return Result


# ---------------------------------------------------------------------------
# Encoding (FIPS 203, Section 4.2)
# ---------------------------------------------------------------------------

def ByteEncode(Coefficients, D):
	"""Encode 256 coefficients as 32*D bytes (FIPS 203, Algorithm 5).

	Args:
		Coefficients: Values modulo 2^D for D < 12, or modulo q for D = 12.
		D: Bit width, 1..12.
	Returns:
		A byte string of length 32*D, least-significant bit first.
	"""
	# D-bit little-endian encoding of 256 coefficients (FIPS 203, Algorithm 5).
	Result = bytearray()
	Accumulator = 0
	BitCount = 0
	Modulus = Q if (D == 12) else (1 << D)
	for Coefficient in Coefficients:
		Accumulator |= (Coefficient % Modulus) << BitCount
		BitCount += D
		while BitCount >= 8:
			Result.append(Accumulator & 0xFF)
			Accumulator >>= 8
			BitCount -= 8
	if BitCount > 0:
		Result.append(Accumulator & 0xFF)
	return bytes(Result)


def ByteEncode12(Coefficients):
	"""Encode 256 coefficients into 384 bytes with d = 12 (Algorithm 5).

	Args:
		Coefficients: 256 integers modulo q.
	Returns:
		A 384-byte string.
	"""
	# 12-bit encoding of 256 coefficients into 384 bytes (Algorithm 5, d = 12).
	return ByteEncode(Coefficients, 12)


def ByteDecode(ByteString, D):
	"""Decode 32*D bytes into 256 coefficients (FIPS 203, Algorithm 6).

	Args:
		ByteString: Exactly 32*D bytes.
		D: Bit width, 1..12.
	Returns:
		256 integers modulo 2^D for D < 12, or modulo q for D = 12.
	"""
	# Inverse of ByteEncode (FIPS 203, Algorithm 6).
	Bits = BytesToBits(ByteString)
	Modulus = Q if (D == 12) else (1 << D)
	Coefficients = []
	for i in range(N):
		Value = 0
		for j in range(D):
			Value |= Bits[i * D + j] << j
		Coefficients.append(Value % Modulus)
	return Coefficients


def Compress(Coefficient, D):
	"""Round (2^D / q) * Coefficient modulo 2^D (FIPS 203, Eq. 4.7).

	Args:
		Coefficient: Integer modulo q.
		D: Compression bit width.
	Returns:
		An integer in [0, 2^D).
	"""
	# Round (2^D / q) * Coefficient modulo 2^D (FIPS 203, Equation 4.7).
	return ((Coefficient * (1 << D) + (Q // 2)) // Q) % (1 << D)


def Decompress(Value, D):
	"""Round (q / 2^D) * Value (FIPS 203, Equation 4.8).

	Args:
		Value: Integer in [0, 2^D).
		D: Decompression bit width.
	Returns:
		An integer modulo q.
	"""
	# Round (q / 2^D) * Value (FIPS 203, Equation 4.8).
	return (Q * Value + (1 << (D - 1))) // (1 << D)


# ---------------------------------------------------------------------------
# ML-KEM key generation
# ---------------------------------------------------------------------------

def ML_KEM_KeyGen(ParameterSet, D=None, Z=None):
	"""Generate an ML-KEM encapsulation/decapsulation key pair (Algorithm 19).

	Args:
		ParameterSet: 512, 768 or 1024.
		D: Optional 32-byte seed for deterministic testing; random when omitted.
		Z: Optional 32-byte implicit-rejection seed; random when omitted.
	Returns:
		A pair (ek, dk) of raw byte strings.
	"""
	# ML-KEM.KeyGen (FIPS 203, Algorithm 19): draw d and z, then run
	# ML-KEM.KeyGen_internal (Algorithm 16), which calls K-PKE.KeyGen (Algorithm 13).
	Params = PARAMETER_SETS[ParameterSet]
	k = Params["k"]
	Eta1 = Params["eta1"]

	# Fresh 32-byte seeds from the operating-system RBG (FIPS 203, Section 3.3),
	# unless supplied by the caller for deterministic testing.
	if D is None:
		D = secrets.token_bytes(32)
	if Z is None:
		Z = secrets.token_bytes(32)

	# (rho, sigma) = G(d || byte(k)).
	Rho, Sigma = G(D + bytes([k]))

	# A_hat[i][j] = SampleNTT(XOF(rho, j, i)); column index first.
	A_hat = SampleMatrix(Rho, k)

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


# Command-line entry point. Importing this module has no side effects.
def Main():
	"""Run the key generation command-line interface."""
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
		print(f"Time Taken = {Duration:.4f} Sec")

	except Exception as Error:
		print("Error:", Error)
		exit(1)

	print("\n")
	exit(0)


if (__name__ == "__main__"):
	Main()

"""
"""
