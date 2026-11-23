#!/usr/bin/python3   

"""
"" 21st November 2026 ::: Daniyal Anis, Sarbo Sarcar, Srijani Roy  
"" 
"" Usage : python3 decap.py <parameter_set>
""
"" <parameter_set> : ML-KEM parameter set. Allowed values are 512, 768 and 1024.
""
"" This Program performs ML-KEM decapsulation (FIPS 203, Algorithm 21) for the
"" selected parameter set. It reads dk.bin and ct.bin, runs K-PKE.Decrypt
"" (Algorithm 15) to recover a candidate message, and calls
"" ML-KEM.Decaps_internal (Algorithm 18), which re-encrypts that message to check
"" the ciphertext. On a mismatch it returns the implicit-rejection value
"" K_bar = J(z || c) instead of an error.
""
"" The Program writes the recovered 32-byte shared secret to K_decap.bin in the
"" current working directory and reports whether it matches K_encap.bin. It can
"" also be imported: call ML_KEM_Decaps(Dk, C, ParameterSet).
""
"" Run keygen.py and encap.py first to produce dk.bin and ct.bin.
""
"" Sample Input/Output Sets                 
""
"" Only 512, 768 and 1024 are valid, so the sets repeat; each run uses the keys
"" and ciphertext already present in the working directory.
""
"" INPUT 1:-
"" Execution: python3 decap.py 512
"" OUTPUT 1:-
"" ML-KEM-512 decapsulation done.
"" dk.bin : 1632 bytes
"" ct.bin : 768 bytes
"" K_decap.bin : 32 bytes
"" Shared secrets match.
"" Time Taken = 0.0071 Sec (Macbook Air M3)
""
"" INPUT 2:-
"" Execution: python3 decap.py 768
"" OUTPUT 2:-
"" ML-KEM-768 decapsulation done.
"" dk.bin : 2400 bytes
"" ct.bin : 1088 bytes
"" K_decap.bin : 32 bytes
"" Shared secrets match.
"" Time Taken = 0.0103 Sec (Macbook Air M3)
""
"" INPUT 3:-
"" Execution: python3 decap.py 1024
"" OUTPUT 3:-
"" ML-KEM-1024 decapsulation done.
"" dk.bin : 3168 bytes
"" ct.bin : 1568 bytes
"" K_decap.bin : 32 bytes
"" Shared secrets match.
"" Time Taken = 0.0143 Sec (Macbook Air M3)
""
"" INPUT 4:-
"" Execution: python3 decap.py 512
"" OUTPUT 4:-
"" ML-KEM-512 decapsulation done.
"" dk.bin : 1632 bytes
"" ct.bin : 768 bytes
"" K_decap.bin : 32 bytes
"" Shared secrets match.
"" Time Taken = 0.0073 Sec (Macbook Air M3)
""
"" INPUT 5:-
"" Execution: python3 decap.py 768
"" OUTPUT 5:-
"" ML-KEM-768 decapsulation done.
"" dk.bin : 2400 bytes
"" ct.bin : 1088 bytes
"" K_decap.bin : 32 bytes
"" Shared secrets match.
"" Time Taken = 0.0105 Sec (Macbook Air M3)
""
"" INPUT 6:-
"" Execution: python3 decap.py 1024
"" OUTPUT 6:-
"" ML-KEM-1024 decapsulation done.
"" dk.bin : 3168 bytes
"" ct.bin : 1568 bytes
"" K_decap.bin : 32 bytes
"" Shared secrets match.
"" Time Taken = 0.0141 Sec (Macbook Air M3)
""
"" INPUT 7:-
"" Execution: python3 decap.py 512
"" OUTPUT 7:-
"" ML-KEM-512 decapsulation done.
"" dk.bin : 1632 bytes
"" ct.bin : 768 bytes
"" K_decap.bin : 32 bytes
"" Shared secrets match.
"" Time Taken = 0.0071 Sec (Macbook Air M3)
""
"" INPUT 8:-
"" Execution: python3 decap.py 768
"" OUTPUT 8:-
"" ML-KEM-768 decapsulation done.
"" dk.bin : 2400 bytes
"" ct.bin : 1088 bytes
"" K_decap.bin : 32 bytes
"" Shared secrets match.
"" Time Taken = 0.0105 Sec (Macbook Air M3)
""
"" INPUT 9:-
"" Execution: python3 decap.py 1024
"" OUTPUT 9:-
"" ML-KEM-1024 decapsulation done.
"" dk.bin : 3168 bytes
"" ct.bin : 1568 bytes
"" K_decap.bin : 32 bytes
"" Shared secrets match.
"" Time Taken = 0.0142 Sec (Macbook Air M3)
""
"" INPUT 10:-
"" Execution: python3 decap.py 512
"" OUTPUT 10:-
"" ML-KEM-512 decapsulation done.
"" dk.bin : 1632 bytes
"" ct.bin : 768 bytes
"" K_decap.bin : 32 bytes
"" Shared secrets match.
"" Time Taken = 0.0071 Sec (Macbook Air M3)
""
"" Input Details
"" - parameter_set : 512, 768 or 1024 (no default).
"" - dk.bin : decapsulation key produced by keygen.py.
"" - ct.bin : ciphertext produced by encap.py.
"" 
"" Output Details
"" - K_decap.bin : raw 32-byte recovered shared secret.
"" 
"" Time Taken ::: System Details
"" - The elapsed time is printed at run time; the values above were measured on a Macbook Air M3 with python3 (CPython 3.9.6).
""
"""

from keygen import *
from encap import K_PKE_Encrypt
import os
import sys
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

USAGE="Usage : python3 decap.py <parameter_set>"


# ---------------------------------------------------------------------------
# K-PKE decryption (FIPS 203, Algorithm 15)
# ---------------------------------------------------------------------------

def K_PKE_Decrypt(Dk, C, Params):
	"""Decrypt a K-PKE ciphertext to recover the message.

	Args:
		Dk: K-PKE decryption key bytes (384*k), the first part of dk.
		C: Ciphertext bytes of length 32*(du*k + dv).
		Params: Parameter dictionary from PARAMETER_SETS.
	Returns:
		The recovered 32-byte message.
	"""
	# K-PKE.Decrypt.
	k = Params["k"]
	Du = Params["du"]
	Dv = Params["dv"]

	# Split the ciphertext into c1 and c2, then decompress u and v.
	C1 = C[0:32 * Du * k]
	C2 = C[32 * Du * k:]
	U = [[Decompress(Value, Du) for Value in ByteDecode(C1[32 * Du * i:32 * Du * (i + 1)], Du)] for i in range(k)]
	V = [Decompress(Value, Dv) for Value in ByteDecode(C2, Dv)]

	# Decode s_hat from the K-PKE decryption key.
	S_hat = [ByteDecode(Dk[384 * j:384 * (j + 1)], 12) for j in range(k)]

	# w = v - NTT^-1(s_hat^T o NTT(u)) (FIPS 203, Algorithm 15, step 6).
	U_hat = [NTT(Poly) for Poly in U]
	Product = [0] * N
	for j in range(k):
		Term = MultiplyNTTs(S_hat[j], U_hat[j])
		for x in range(N):
			Product[x] = (Product[x] + Term[x]) % Q
	Poly = NTTInverse(Product)
	W = [(V[x] - Poly[x]) % Q for x in range(N)]

	return ByteEncode([Compress(Coefficient, 1) for Coefficient in W], 1)


# ---------------------------------------------------------------------------
# ML-KEM decapsulation
# ---------------------------------------------------------------------------

def ML_KEM_Decaps_Internal(Dk, C, ParameterSet):
	"""Recover a shared secret with implicit rejection.

	Args:
		Dk: Decapsulation key bytes (768*k + 96).
		C: Ciphertext bytes.
		ParameterSet: 512, 768 or 1024.
	Returns:
		A 32-byte shared secret; J(z || c) if re-encryption does not match c.
	"""
	# ML-KEM.Decaps_internal (FIPS 203, Algorithm 18).
	if (ParameterSet not in PARAMETER_SETS):
		raise ValueError("parameter_set should be 512, 768 or 1024.")
	Params = PARAMETER_SETS[ParameterSet]
	k = Params["k"]

	# Parse the decapsulation key into dkPKE, ekPKE, h and z.
	Dk_PKE = Dk[0:384 * k]
	Ek = Dk[384 * k:768 * k + 32]
	h = Dk[768 * k + 32:768 * k + 64]
	z = Dk[768 * k + 64:768 * k + 96]

	# Recover m', derive (K', r'), and compute the implicit-rejection key.
	M = K_PKE_Decrypt(Dk_PKE, C, Params)
	K, R = G(M + h)
	K_bar = J(z + C)

	# Re-encrypt and compare; a mismatch selects K_bar.
	C_prime = K_PKE_Encrypt(Ek, M, R, Params)
	if (C != C_prime):
		K = K_bar
	return K


def ML_KEM_Decaps(Dk, C, ParameterSet):
	"""Decapsulate after validating all inputs.

	Args:
		Dk: Decapsulation key bytes; length and hash are checked.
		C: Ciphertext bytes; length is checked.
		ParameterSet: 512, 768 or 1024.
	Returns:
		The 32-byte recovered shared secret.
	Raises:
		ValueError: If the parameter set, key or ciphertext is invalid.
	"""
	# ML-KEM.Decaps (FIPS 203, Algorithm 21), including the input checks from
	# Section 7.3: ciphertext length, decapsulation key length, and hash check.
	if (ParameterSet not in PARAMETER_SETS):
		raise ValueError("parameter_set should be 512, 768 or 1024.")
	Params = PARAMETER_SETS[ParameterSet]
	k = Params["k"]
	if (len(C) != 32 * (Params["du"] * k + Params["dv"])):
		raise ValueError("Ciphertext has the wrong length.")
	if (len(Dk) != 768 * k + 96):
		raise ValueError("Decapsulation key has the wrong length.")
	if (H(Dk[384 * k:768 * k + 32]) != Dk[768 * k + 32:768 * k + 64]):
		raise ValueError("Decapsulation key failed the hash check.")
	return ML_KEM_Decaps_Internal(Dk, C, ParameterSet)


# Command-line entry point. Importing this module has no side effects.
def Main():
	"""Run the decapsulation command-line interface."""
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
		with open("dk.bin", "rb") as Dk_File:
			Dk = Dk_File.read()
		with open("ct.bin", "rb") as Ct_File:
			Ct = Ct_File.read()

		Start_Time = time.time()
		K = ML_KEM_Decaps(Dk, Ct, Parameter_Set)
		Duration = time.time() - Start_Time

		with open("K_decap.bin", "wb") as K_File:
			K_File.write(K)

		print(f"ML-KEM-{Parameter_Set} decapsulation done.")
		print(f"dk.bin : {len(Dk)} bytes")
		print(f"ct.bin : {len(Ct)} bytes")
		print(f"K_decap.bin : {len(K)} bytes")
		if (os.path.exists("K_encap.bin")):
			with open("K_encap.bin", "rb") as K_File:
				K_Encap = K_File.read()
			if (K == K_Encap):
				print("Shared secrets match.")
			else:
				print("Shared secrets differ.")
		else:
			print("K_encap.bin not found; skipping comparison.")
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
