import hashlib
import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# Small test parameters for Diffie-Hellman
q = 0xB10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371 # Prime modulus
alpha = 0xA4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5  # Generator

#alpha = 1
#alpha = q
#alpha = q-1

# Simulate Alice, Mallory, and Bob's Diffie-Hellman key exchange

# Step 2: Alice's Key Computation
X_A = random.randint(1, q - 1)  # Alice's private key
Y_A = pow(alpha, X_A, q)  # Alice's public key

print("Alice's Private Key (X_A):", X_A)
print("Alice's Public Key (Y_A):", Y_A)

# Step 3: Bob's Key Computation
X_B = random.randint(1, q - 1)  # Bob's private key
Y_B = pow(alpha, X_B, q)  # Bob's public key

print("Bob's Private Key (X_B):", X_B)
print("Bob's Public Key (Y_B):", Y_B)

# Step 4: Mallory Intercepts and Modifies the Public Keys
# Mallory intercepts the keys and sends q instead of Y_A and Y_B
Y_A_modified = q  # Mallory sends q to Bob instead of Y_A
Y_B_modified = q  # Mallory sends q to Alice instead of Y_B

# Alice computes shared secret using modified Y_B (Mallory's tampered Y_B)
s_Alice = pow(Y_B_modified, X_A, q)
#s_Alice = pow(Y_B, X_A, q)


# Bob computes shared secret using modified Y_A (Mallory's tampered Y_A)
s_Bob = pow(Y_A_modified, X_B, q)
#s_Bob = pow(Y_A, X_B, q)


print("Shared Secret Computed by Alice (s_Alice):", s_Alice)
print("Shared Secret Computed by Bob (s_Bob):", s_Bob)

# Verify if both computed the same shared secret
assert s_Alice == s_Bob, "Shared secrets do not match!"

# Step 5: Hashing the Shared Secret
# SHA-256 of the shared secret and truncating to 16 bytes
shared_secret_bytes = s_Alice.to_bytes((s_Alice.bit_length() + 7) // 8, byteorder='big')
k = hashlib.sha256(shared_secret_bytes).digest()[:16]

print("Symmetric Key (k):", k.hex())

# Step 6: Encrypt and Decrypt Messages Using AES-CBC

# Alice's message to Bob
m0 = "Hi Bob!".encode()

# AES-CBC Encryption
iv = get_random_bytes(16)  # Initialization Vector
cipher = AES.new(k, AES.MODE_CBC, iv)
ciphertext = cipher.encrypt(pad(m0, AES.block_size))

print("Encrypted message (c0):", ciphertext.hex())

# Mallory intercepts and decrypts
cipher = AES.new(k, AES.MODE_CBC, iv)
decrypted_message = unpad(cipher.decrypt(ciphertext), AES.block_size)

print("Decrypted message by Mallory:", decrypted_message.decode())

# Bob's message to Alice
m1 = "Hi Alice!".encode()

# AES-CBC Encryption by Bob
cipher = AES.new(k, AES.MODE_CBC, iv)
ciphertext_bob = cipher.encrypt(pad(m1, AES.block_size))

print("Encrypted message (c1):", ciphertext_bob.hex())

# Mallory intercepts and decrypts
cipher = AES.new(k, AES.MODE_CBC, iv)
decrypted_message_bob = unpad(cipher.decrypt(ciphertext_bob), AES.block_size)

print("Decrypted message by Mallory:", decrypted_message_bob.decode())
