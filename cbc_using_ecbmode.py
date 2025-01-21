from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import os


key = get_random_bytes(16)  # 16-byte key for AES


def encrypt_bmp(input_file, encrypted_file):
    with open(input_file, "rb") as bmp_file:
        bmp_data = bmp_file.read()

    header = bmp_data[:54]
    pixel_data = bmp_data[54:]

    cipher = AES.new(key, AES.MODE_ECB)
    padded_data = pad(pixel_data, AES.block_size, style='pkcs7')

    iv = get_random_bytes(AES.block_size)
    prev_result = iv
    encrypted_data = bytearray()

    for i in range(0, len(padded_data), AES.block_size):
        block = padded_data[i:i + AES.block_size]
        xored_block = bytes(a ^ b for a, b in zip(block, prev_result))
        encrypted_block = cipher.encrypt(xored_block)
        encrypted_data.extend(encrypted_block)
        prev_result = encrypted_block

    with open(encrypted_file, "wb") as enc_file:
        enc_file.write(header)
        enc_file.write(iv)
        enc_file.write(encrypted_data)

    print(f"Encrypted BMP written to: {encrypted_file}")


def decrypt_bmp(encrypted_file, output_file):
    with open(encrypted_file, "rb") as enc_file:
        bmp_data = enc_file.read()

    header = bmp_data[:54]
    iv = bmp_data[54:70]
    encrypted_data = bmp_data[70:]


    cipher = AES.new(key, AES.MODE_ECB)
    prev_result = iv
    decrypted_data = bytearray()

    for i in range(0, len(encrypted_data), AES.block_size):
        block = encrypted_data[i:i + AES.block_size]
        decrypted_block = cipher.decrypt(block)
        xored_block = bytes(a ^ b for a, b in zip(decrypted_block, prev_result))
        decrypted_data.extend(xored_block)
        prev_result = block  # Update the previous result

    pixel_data = unpad(decrypted_data, AES.block_size, style='pkcs7')

    with open(output_file, "wb") as out_file:
        out_file.write(header)
        out_file.write(pixel_data)

    print(f"Decrypted BMP written to: {output_file}")


# Paths to the files
original_bmp = "cp-logo.bmp"
encrypted_bmp = "encrypted_logo.bmp"
decrypted_bmp = "decrypted_logo.bmp"

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
