from Crypto.Hash import SHA256
import bcrypt
import base64
import random
import string
import time

import nltk
from nltk.corpus import words


def parse_file(file_path):
    users = []

    with open(file_path, 'r') as file:
        for line in file:
            line = line.strip()

            name, hash_data = line.split(":")

            # Extract work factor, salt, and hash
            parts = hash_data.split('$')
            workfactor = parts[2]  # Convert work factor to integer

            salt = parts[3][:22]  # Extract the first 22 characters after the $
            hash_value = parts[3][22:]  # The rest is the hash

            # Append to the users list
            users.append([name, workfactor, salt, hash_value])

    return users
file_path = "shadow.txt"
users = parse_file(file_path)



def hash(input, salt):
    # Hash the password
    hashed = bcrypt.hashpw(input.encode('utf-8'), salt)
    return hashed

if __name__ == "__main__":

    # Get all words from the NLTK word corpus
    word_list = words.words()

    words_sixtoten = [word for word in word_list if 6 <= len(word) <= 10]

    for i in range (len(users)):
        timestart = time.time()
        for j in range(len(words_sixtoten)):
            if (j%1000 == 0):
                print("words checked:", i + 1, ": ", j)
            salt = f"$2b${users[i][1]}${users[i][2]}"
            userhash = f"$2b${users[i][1]}${users[i][2]}{users[i][3]}"

            #   print(userhash.encode('utf-8'), "==?==", hash(words_sixtoten[j], salt.encode('utf-8')))
            if (userhash.encode('utf-8') == hash(words_sixtoten[j], salt.encode('utf-8'))):
                print("\n\nSuccess! password:", words_sixtoten[j], "\nTime taken: ", time.time()-timestart, "\nWords checked: ", j)


