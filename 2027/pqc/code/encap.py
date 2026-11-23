#!/usr/bin/python3   

"""
"" 21st November 2026 ::: Daniyal Anis, Sarbo Sarcar, Srijani Roy  
"" 
"" Usage : python3 encap.py <parameter_set>
""
"" <parameter_set> : ML-KEM parameter set. Allowed values are 512, 768 and 1024.
""
"" This Program performs ML-KEM encapsulation (FIPS 203, Algorithm 20) for the
"" selected parameter set. It reads ek.bin, draws a fresh 32-byte message m, and
"" runs ML-KEM.Encaps_internal (Algorithm 17), which derives (K, r) = G(m || H(ek))
"" and encrypts m with K-PKE.Encrypt (Algorithm 14).
""
"" The Program writes the ciphertext to ct.bin and the 32-byte shared secret to
"" K_encap.bin in the current working directory. It can also be imported: call
"" ML_KEM_Encaps(Ek, ParameterSet), or ML_KEM_Encaps_Internal(Ek, ParameterSet, M)
"" with a caller-supplied message for deterministic testing.
""
"" Run keygen.py first to produce ek.bin.
""
"" Sample Input/Output Sets                 
""
"" Only 512, 768 and 1024 are valid, so the sets repeat; every run draws a fresh
"" random message.
""
"" INPUT 1:-
"" Execution: python3 encap.py 512
"" OUTPUT 1:-
"" ML-KEM-512 encapsulation done.
"" ek.bin : 800 bytes
"" ct.bin : 768 bytes
"" K_encap.bin : 32 bytes
"" Time Taken = 0.0051 Sec (Macbook Air M3)
""
"" INPUT 2:-
"" Execution: python3 encap.py 768
"" OUTPUT 2:-
"" ML-KEM-768 encapsulation done.
"" ek.bin : 1184 bytes
"" ct.bin : 1088 bytes
"" K_encap.bin : 32 bytes
"" Time Taken = 0.0078 Sec (Macbook Air M3)
""
"" INPUT 3:-
"" Execution: python3 encap.py 1024
"" OUTPUT 3:-
"" ML-KEM-1024 encapsulation done.
"" ek.bin : 1568 bytes
"" ct.bin : 1568 bytes
"" K_encap.bin : 32 bytes
"" Time Taken = 0.0107 Sec (Macbook Air M3)
""
"" INPUT 4:-
"" Execution: python3 encap.py 512
"" OUTPUT 4:-
"" ML-KEM-512 encapsulation done.
"" ek.bin : 800 bytes
"" ct.bin : 768 bytes
"" K_encap.bin : 32 bytes
"" Time Taken = 0.0054 Sec (Macbook Air M3)
""
"" INPUT 5:-
"" Execution: python3 encap.py 768
"" OUTPUT 5:-
"" ML-KEM-768 encapsulation done.
"" ek.bin : 1184 bytes
"" ct.bin : 1088 bytes
"" K_encap.bin : 32 bytes
"" Time Taken = 0.0075 Sec (Macbook Air M3)
""
"" INPUT 6:-
"" Execution: python3 encap.py 1024
"" OUTPUT 6:-
"" ML-KEM-1024 encapsulation done.
"" ek.bin : 1568 bytes
"" ct.bin : 1568 bytes
"" K_encap.bin : 32 bytes
"" Time Taken = 0.0111 Sec (Macbook Air M3)
""
"" INPUT 7:-
"" Execution: python3 encap.py 512
"" OUTPUT 7:-
"" ML-KEM-512 encapsulation done.
"" ek.bin : 800 bytes
"" ct.bin : 768 bytes
"" K_encap.bin : 32 bytes
"" Time Taken = 0.0052 Sec (Macbook Air M3)
""
"" INPUT 8:-
"" Execution: python3 encap.py 768
"" OUTPUT 8:-
"" ML-KEM-768 encapsulation done.
"" ek.bin : 1184 bytes
"" ct.bin : 1088 bytes
"" K_encap.bin : 32 bytes
"" Time Taken = 0.0078 Sec (Macbook Air M3)
""
"" INPUT 9:-
"" Execution: python3 encap.py 1024
"" OUTPUT 9:-
"" ML-KEM-1024 encapsulation done.
"" ek.bin : 1568 bytes
"" ct.bin : 1568 bytes
"" K_encap.bin : 32 bytes
"" Time Taken = 0.0113 Sec (Macbook Air M3)
""
"" INPUT 10:-
"" Execution: python3 encap.py 512
"" OUTPUT 10:-
"" ML-KEM-512 encapsulation done.
"" ek.bin : 800 bytes
"" ct.bin : 768 bytes
"" K_encap.bin : 32 bytes
"" Time Taken = 0.0058 Sec (Macbook Air M3)
""
"" Input Details
"" - parameter_set : 512, 768 or 1024 (no default).
"" - ek.bin : encapsulation key produced by keygen.py.
"" - Randomness : a fresh 32-byte message m from the operating-system RBG.
"" 
"" Output Details
"" - ct.bin : raw ciphertext, 32*(du*k + dv) bytes.
"" - K_encap.bin : raw 32-byte shared secret.
"" 
"" Time Taken ::: System Details
"" - The elapsed time is printed at run time; the values above were measured on a Macbook Air M3 with python3 (CPython 3.9.6).
""
"""

from keygen import *
import sys
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

USAGE="Usage : python3 encap.py <parameter_set>"


# ---------------------------------------------------------------------------
# K-PKE encryption.
# ---------------------------------------------------------------------------

def K_PKE_Encrypt(Ek, M, R, Params):
	"""Encrypt a 32-byte message with K-PKE.

	Args:
		Ek: Encapsulation key bytes (384*k + 32).
		M: 32-byte message.
		R: 32-byte encryption randomness.
		Params: Parameter dictionary from PARAMETER_SETS.
	Returns:
		Ciphertext bytes c = c1 || c2 of length 32*(du*k + dv).
	"""
	# K-PKE.Encrypt (FIPS 203, Algorithm 14).
	k = Params["k"]
	Eta1 = Params["eta1"]
	Eta2 = Params["eta2"]
	Du = Params["du"]
	Dv = Params["dv"]

	# Decode t_hat and extract rho from the encapsulation key.
	T_hat = [ByteDecode(Ek[384 * j:384 * (j + 1)], 12) for j in range(k)]
	Rho = Ek[384 * k:384 * k + 32]

	# Regenerate the matrix A_hat from rho.
	A_hat = SampleMatrix(Rho, k)

	# Sample y (eta1), e1 (eta2) and e2 (eta2) with nonces 0..2k.
	Nonce = 0
	Y = []
	for i in range(k):
		Y.append(SamplePolyCBD(PRF(R, Nonce, Eta1), Eta1))
		Nonce += 1
	E1 = []
	for i in range(k):
		E1.append(SamplePolyCBD(PRF(R, Nonce, Eta2), Eta2))
		Nonce += 1
	E2 = SamplePolyCBD(PRF(R, Nonce, Eta2), Eta2)

	Y_hat = [NTT(Poly) for Poly in Y]

	# u = NTT^-1(A_hat^T o y_hat) + e1.
	U = []
	for i in range(k):
		Product = [0] * N
		for j in range(k):
			Term = MultiplyNTTs(A_hat[j][i], Y_hat[j])
			for x in range(N):
				Product[x] = (Product[x] + Term[x]) % Q
		Poly = NTTInverse(Product)
		U.append([(Poly[x] + E1[i][x]) % Q for x in range(N)])

	# v = NTT^-1(t_hat^T o y_hat) + e2 + mu.
	Product = [0] * N
	for j in range(k):
		Term = MultiplyNTTs(T_hat[j], Y_hat[j])
		for x in range(N):
			Product[x] = (Product[x] + Term[x]) % Q
	Poly = NTTInverse(Product)
	Mu = [Decompress(Bit, 1) for Bit in ByteDecode(M, 1)]
	V = [(Poly[x] + E2[x] + Mu[x]) % Q for x in range(N)]

	# Compress and serialize c1 || c2.
	C1 = bytearray()
	for Poly in U:
		C1 += ByteEncode([Compress(Coefficient, Du) for Coefficient in Poly], Du)
	C2 = ByteEncode([Compress(Coefficient, Dv) for Coefficient in V], Dv)
	return bytes(C1) + C2


# ---------------------------------------------------------------------------
# ML-KEM encapsulation.
# ---------------------------------------------------------------------------

def ML_KEM_Encaps_Internal(Ek, ParameterSet, M=None):
	"""Derive a shared secret and encrypt m.

	Args:
		Ek: Encapsulation key bytes.
		ParameterSet: 512, 768 or 1024.
		M: Optional 32-byte message; a fresh random one is drawn when omitted.
	Returns:
		A pair (K, c): 32-byte shared secret and ciphertext.
	"""
	# ML-KEM.Encaps_internal.
	if (ParameterSet not in PARAMETER_SETS):
		raise ValueError("parameter_set should be 512, 768 or 1024.")
	Params = PARAMETER_SETS[ParameterSet]
	if (M is None):
		M = secrets.token_bytes(32)
	K, R = G(M + H(Ek))
	C = K_PKE_Encrypt(Ek, M, R, Params)
	return K, C


def ML_KEM_Encaps(Ek, ParameterSet):
	"""Encapsulate after validating the key.

	Args:
		Ek: Encapsulation key bytes; length and modulus are checked.
		ParameterSet: 512, 768 or 1024.
	Returns:
		A pair (K, c): 32-byte shared secret and ciphertext.
	Raises:
		ValueError: If the parameter set or encapsulation key is invalid.
	"""
	# ML-KEM.Encaps (FIPS 203, Algorithm 20), including the encapsulation key
	# type and modulus checks from Section 7.2.
	if (ParameterSet not in PARAMETER_SETS):
		raise ValueError("parameter_set should be 512, 768 or 1024.")
	k = PARAMETER_SETS[ParameterSet]["k"]
	if (len(Ek) != 384 * k + 32):
		raise ValueError("Encapsulation key has the wrong length.")
	T_decoded = []
	for j in range(k):
		T_decoded += ByteDecode(Ek[384 * j:384 * (j + 1)], 12)
	if (ByteEncode(T_decoded, 12) != Ek[0:384 * k]):
		raise ValueError("Encapsulation key failed the modulus check.")
	return ML_KEM_Encaps_Internal(Ek, ParameterSet)


# Command-line entry point. Importing this module has no side effects.
def Main():
	"""Run the encapsulation command-line interface."""
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
		with open("ek.bin", "rb") as Ek_File:
			Ek = Ek_File.read()

		Start_Time = time.time()
		K, Ct = ML_KEM_Encaps(Ek, Parameter_Set)
		Duration = time.time() - Start_Time

		with open("ct.bin", "wb") as Ct_File:
			Ct_File.write(Ct)
		with open("K_encap.bin", "wb") as K_File:
			K_File.write(K)

		print(f"ML-KEM-{Parameter_Set} encapsulation done.")
		print(f"ek.bin : {len(Ek)} bytes")
		print(f"ct.bin : {len(Ct)} bytes")
		print(f"K_encap.bin : {len(K)} bytes")
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
