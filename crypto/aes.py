from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from secrets import token_bytes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def encrypt(data, aad, key=None, nonce=None):
    if key is None:
        key = AESGCM.generate_key(bit_length=256)
    if nonce is None:
        nonce = token_bytes(12)
    aesgcm = AESGCM(key)
    return (aesgcm.encrypt(nonce, data, aad),
            key,
            nonce
            )


def decrypt(key, cData, aad, nonce):
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, cData, aad)


def generateSalt():
    return token_bytes(16)


def generateKey(salt, password):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000
    )
    key = kdf.derive(password)
    return key
