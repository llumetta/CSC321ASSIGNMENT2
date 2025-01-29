from Crypto.Hash import SHA256

import random
import string
import time


DIGEST_LENGTH = 40

def generate_random_string(length):
    """Generate a random string of the specified length."""
    characters = string.ascii_letters + string.digits  # Include letters and numbers
    return ''.join(random.choice(characters) for _ in range(length))


def find_repeat_indices(bin_array):
    seen = {}  # A dictionary to track binary strings and their indices
    for i, bin_str in enumerate(bin_array):
        if bin_str in seen:
            return (seen[bin_str], i)  # Return the indices of the repeat
        seen[bin_str] = i  # Store the binary string with its index
    return None  # No repeats found





def hash(input):
    # Create a new SHA256 hash object
    hash = SHA256.new()
    # Update the hash object with the user input
    hash.update(input.encode('utf-8'))
    # Print the digest in hexadecimal format
    print("SHA256 digest (hex): ", hash.hexdigest())
    digest = hash.hexdigest()
    truncated_hash = bin(int(digest, 16))[2:]
    truncated_hash = truncated_hash[:DIGEST_LENGTH]
    return truncated_hash

if __name__ == "__main__":
    user_input1 = "Enter a string to hash (or type 'exit' to quit): "
    user_input2 = "Enter a string to hash (or type 'exit' to quit):"

    print(hash(user_input1))
    print(hash(user_input2))

    start_time = time.time()
    check = 1
    num_inputs = 0
    while(check):
        array_str = 10000*[""]
        array_digests = 10000*[bin(0)]

        for i in range(10000):
            array_str[i] = generate_random_string(10)
            array_digests[i] = hash(array_str[i])
            num_inputs += 1

        if (find_repeat_indices(array_digests)):
            check=0
            str1 = array_str[find_repeat_indices(array_digests)[0]]
            str2 = array_str[find_repeat_indices(array_digests)[1]]
            digest1 = array_digests[find_repeat_indices(array_digests)[0]]
            digest2 = array_digests[find_repeat_indices(array_digests)[1]]
    end_time = time.time()

    time = end_time - start_time

    print("\nstring: ", str1, "digest: ", digest1,"\n", "string: ", str2, "digest: ", digest2)
    print("Time taken for digest size (", DIGEST_LENGTH, ") :", time)
    print("\nNumber of hashs checked: ", num_inputs)