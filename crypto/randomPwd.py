import secrets
import random


def generatePassword(length=16) -> str:
    # generating lists of ascii alphabet and symbols
    # represented as integers
    asciiList1 = [33, 35, 36, 37, 38, 40, 41, 42, 43]
    asciiList2 = list(range(47, 96))
    asciiList3 = list(range(97, 126))
    asciiListAll = asciiList1 + asciiList2 + asciiList3
    random.shuffle(asciiListAll)
    password = ''.join(
        chr(secrets.choice(asciiListAll)) for _ in range(length)
    )
    return password


# Test
# print(generatePassword())
