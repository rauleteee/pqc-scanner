"""Sample file with quantum-vulnerable cryptography, used to test the scanner.

This is NOT real production code: it serves as a test bench for the detection
phases (AST). It mixes Shor-broken, Grover-weakened and PQC primitives.
"""

from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms


def make_rsa_key():
    # CRITICAL: RSA broken by Shor
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def make_ec_key():
    # CRITICAL: ECC broken by Shor
    return ec.generate_private_key(ec.SECP256R1())


def make_aes_cipher(key, iv):
    # MEDIUM: AES-128 weakened by Grover
    return Cipher(algorithms.AES(key), None)


# A comment mentioning rsa.generate_private_key must not produce a finding.
rsa_variable_name = "this is not a call either"
