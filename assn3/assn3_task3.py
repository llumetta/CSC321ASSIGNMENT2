import random
from Crypto.Util import number
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib

# Generate large prime numbers for RSA key generation
def generate_prime(bits):
    return number.getPrime(bits)

# Compute the modular inverse of e mod phi(n)
def modinv(a, m):
    m0, x0, x1 = m, 0, 1
    if m == 1:
        return 0
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    if x1 < 0:
        x1 += m0
    return x1

# RSA Key Generation
def generate_rsa_keys(bits):
    # Generate two large primes p and q
    p = generate_prime(bits)
    q = generate_prime(bits)
    n = p * q
    phi_n = (p - 1) * (q - 1)

    # Public exponent e (commonly 65537)
    e = 65537

    # Private exponent d (modular inverse of e mod phi_n)
    d = modinv(e, phi_n)

    return (n, e, d), (n, d)  # Public and private keys

# RSA Encryption
def rsa_encrypt(public_key, plaintext):
    n, e = public_key
    return pow(plaintext, e, n)

# RSA Decryption
def rsa_decrypt(private_key, ciphertext):
    n, d = private_key
    return pow(ciphertext, d, n)

# Test the RSA functions
def test_rsa():
    # Generate RSA keys with 2048-bit primes
    public_key, private_key = generate_rsa_keys(2048)

    # Convert a message to an integer (ASCII to integer)
    message = "Hello, RSA!".encode("utf-8")
    message_int = int.from_bytes(message, byteorder="big")

    # Encrypt and Decrypt the message
    ciphertext = rsa_encrypt(public_key, message_int)
    decrypted_message_int = rsa_decrypt(private_key, ciphertext)

    # Convert the decrypted integer back to a message
    decrypted_message = decrypted_message_int.to_bytes((decrypted_message_int.bit_length() + 7) // 8, byteorder="big").decode("utf-8")

    print(f"Original message: {message.decode()}")
    print(f"Decrypted message: {decrypted_message}")

test_rsa()