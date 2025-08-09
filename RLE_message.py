#Justin Iwata Made this
from itertools import count


def rle_encode(message):
    encoded = ""
    count = 1
    for i in range(1, len(message) + 1):
        if i < len(message) and message[i] == message[i - 1]:
            count += 1
        else:
            encoded += str(count) + message[i - 1]
            count = 1
    return encoded


def rle_decode(encoded):
    decoded = ""
    count_str = ""
    for ch in encoded:
        if ch.isdigit():
            count_str += ch
        else:
            if count_str == "":
                raise ValueError(f"Missing count before '{ch}'")
            count = int(count_str)   # Convert to int
            decoded += ch * count    # Now this will work with it being converted to int
            count_str = ""
    return decoded


# Main Program with it asking the following 
msg = input("Enter message to send : ")
encoded_msg = rle_encode(msg)
print("Encoded message (sent) : ", encoded_msg)

decoded_msg = rle_decode(encoded_msg)
print("Decoded message (received) : ", decoded_msg)
