'''
20 November 2026

Authors:
- Sarbo Sarcar (002311001011)
- Daniyal Anis (002311001022)
- Srijani Roy (002311001026)

Project: B.E. Final Year Project - Post-Quantum Cryptography
File: keygen.py
Scope: ML-KEM key generation

Purpose:
- Generate the FIPS 203 encapsulation key (ek) and decapsulation key (dk).
- Use SageMath for polynomial-ring and modular arithmetic.
- Keep encapsulation and decapsulation outside this module.

Usage:
    sage keygen.py <parameter_id> [--out-dir <directory>]

Arguments:
- parameter_id: required integer selecting the parameter set:
      1 -> ML-KEM-512
      2 -> ML-KEM-768
      3 -> ML-KEM-1024
- --out-dir: optional output directory; default is ./keys.
- Random seeds and intermediate values are generated internally, not supplied
  as command-line arguments.

Key-generation configuration:

  Parameter                  ML-KEM-512   ML-KEM-768   ML-KEM-1024
  parameter_id                    1            2             3
  n                              256          256           256
  q                             3329         3329          3329
  k                                2            3             4
  eta_1                            3            2             2
  Required RBG strength          128 bits     192 bits      256 bits
  ek length                      800 bytes   1184 bytes    1568 bytes
  dk length                     1632 bytes   2400 bytes    3168 bytes

  Ring: R_q = (Z/3329Z)[X] / (X^256 + 1).

Data conventions:
- MLKEMParameters: immutable record containing the selected set and values above.
- RingContext: SageMath coefficient ring Z_q and quotient ring R_q.
- CoefficientVector / NTTVector: 256 coefficients in Z_q.
- NTTMatrix: k-by-k matrix of NTTVector entries.
- Keys, seeds, and hash/XOF outputs are Python bytes.

Required methods:

1. select_parameter_set(parameter_id: int) -> MLKEMParameters
   Resolve selector 1, 2, or 3; reject all other values.

2. validate_parameters(params: MLKEMParameters) -> None
   Check the selected parameter record and its fixed values.

3. build_ring_context(params: MLKEMParameters) -> RingContext
   Construct Z_q and R_q using SageMath.

4. generate_random_bytes(length: int, strength_bits: int) -> bytes
   Obtain bytes from the configured cryptographically secure RBG backend.

5. h_sha3_256(data: bytes) -> bytes 
   Return the 32-byte SHA3-256 digest.

6. g_sha3_512(data: bytes) -> tuple[bytes, bytes]
   Return the two 32-byte halves of the SHA3-512 digest.

7. prf_eta(seed: bytes, counter: int, eta: int) -> bytes
   Return the SHAKE256 output required by the centred-binomial sampler.

8. sample_ntt(input_bytes: bytes, params: MLKEMParameters) -> NTTVector
   Generate one NTT-domain polynomial.

9. sample_poly_cbd(input_bytes: bytes, eta: int,
                   params: MLKEMParameters) -> CoefficientVector
   Generate one polynomial from the prescribed noise distribution.

10. ntt(poly: CoefficientVector, params: MLKEMParameters) -> NTTVector
    Transform a polynomial to the NTT representation.

11. base_case_multiply(a0, a1, b0, b1, gamma, params) -> tuple
    Multiply one prescribed pair of NTT components.

12. multiply_ntts(f_hat: NTTVector, g_hat: NTTVector,
                  params: MLKEMParameters) -> NTTVector
    Perform FIPS-compatible NTT-domain multiplication.

13. byte_encode(values, d: int) -> bytes
    Encode a polynomial/vector using the requested bit width; key generation
    uses d = 12.

14. expand_matrix_ntt(rho: bytes, params: MLKEMParameters) -> NTTMatrix
    Build the k-by-k public matrix in the NTT domain.

15. sample_keygen_vectors(sigma: bytes, params: MLKEMParameters) -> tuple
    Sample the secret and error polynomial vectors; return (s, e).

16. k_pke_keygen(d: bytes, params: MLKEMParameters) -> tuple
    Return (ek_pke, dk_pke).

17. ml_kem_keygen_internal(d: bytes, z: bytes,
                           params: MLKEMParameters) -> tuple
    Return the final (ek, dk); intended for
    deterministic testing when d and z are supplied by a test harness.

18. ml_kem_keygen(params: MLKEMParameters) -> tuple
    Generate fresh internal seeds and return (ek, dk).

19. validate_key_lengths(ek: bytes, dk: bytes,
                         params: MLKEMParameters) -> None
    Check the output lengths against the selected parameter set.

20. write_key_files(ek: bytes, dk: bytes, out_dir: Path,
                   params: MLKEMParameters) -> tuple[Path, Path]
    Save the raw key bytes and return the two output paths.

21. parse_args(argv: list[str] | None = None) -> argparse.Namespace
    Parse the required parameter selector and optional output directory.

22. main(argv: list[str] | None = None) -> int
    Validate arguments, run key generation, validate and save keys, report
    non-secret output details and execution duration, then return a status code.

Output contract:
- Public key: mlkem_<level>_ek.bin
- Private key: mlkem_<level>_dk.bin
- Both files contain raw FIPS 203 key bytes without headers or metadata.
- Never print, log, or expose d, z, rho, sigma, s, e, or dk.
- Protect the private-key file with restrictive permissions where supported.
- The RBG backend must meet the selected parameter set's required strength;
  do not claim FIPS validation unless the backend and implementation are validated.

Sample run

Input:

Execution:

Output:

Execution duration:

'''

