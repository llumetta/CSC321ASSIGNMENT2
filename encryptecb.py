from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import os

# AES-EBC uses 16-byte blocks. Both key and data must be 16 bytes.
key = get_random_bytes(16)  # 16-byte key for AES

def encrypt_bmp(input_file, encrypted_file):
    # Read the original BMP file
    with open(input_file, "rb") as bmp_file:
        bmp_data = bmp_file.read()

    # Extract the header (first 54 bytes) and the pixel data
    header = bmp_data[:54]  # BMP header is 54 bytes
    pixel_data = bmp_data[54:]  # Remaining is the pixel data

    # Encrypt the pixel data using AES in ECB mode
    cipher = AES.new(key, AES.MODE_ECB)
    padded_data = pad(pixel_data, AES.block_size, style='pkcs7')
    encrypted_data = cipher.encrypt(padded_data)

    # Write the header and encrypted pixel data to the new file
    with open(encrypted_file, "wb") as enc_file:
        enc_file.write(header)  # Write the unencrypted header
        enc_file.write(encrypted_data)  # Write the encrypted pixel data

    print(f"Encrypted BMP written to: {encrypted_file}")


def decrypt_bmp(encrypted_file, output_file):
    # Read the encrypted BMP file
    with open(encrypted_file, "rb") as enc_file:
        bmp_data = enc_file.read()

    # Extract the header and encrypted pixel data
    header = bmp_data[:54]  # First 54 bytes are the BMP header
    encrypted_data = bmp_data[54:]  # Remaining bytes are the encrypted pixel data

    # Decrypt the pixel data using AES in ECB mode
    cipher = AES.new(key, AES.MODE_ECB)
    padded_data = cipher.decrypt(encrypted_data)
    pixel_data = unpad(padded_data, AES.block_size, style='pkcs7')

    # Write the header and decrypted pixel data to the output file
    with open(output_file, "wb") as out_file:
        out_file.write(header)  # Write the unencrypted header
        out_file.write(pixel_data)  # Write the decrypted pixel data

    print(f"Decrypted BMP written to: {output_file}")


# Paths to the files
original_bmp = "cp-logo.bmp"         # Input BMP file
encrypted_bmp = "encrypted_logo.bmp"  # Encrypted BMP file
decrypted_bmp = "decrypted_logo.bmp"  # Decrypted BMP file

# Perform encryption and decryption
try:
    # Encrypt the BMP file
    encrypt_bmp(original_bmp, encrypted_bmp)

    # Decrypt the BMP file
    decrypt_bmp(encrypted_bmp, decrypted_bmp)

    # Compare original and decrypted files
    if os.path.exists(original_bmp) and os.path.exists(decrypted_bmp):
        with open(original_bmp, "rb") as f1, open(decrypted_bmp, "rb") as f2:
            if f1.read() == f2.read():
                print("The original and decrypted BMP files are identical.")
            else:
                print("The original and decrypted BMP files differ.")

except Exception as e:
    print(f"An error occurred: {e}")
