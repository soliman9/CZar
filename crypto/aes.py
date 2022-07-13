from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from os import urandom


def encrypt(data, aad, key=None, nonce=None):
    if key is None:
        key = AESGCM.generate_key(bit_length=256)
    if nonce is None:
        nonce = urandom(12)
    aesgcm = AESGCM(key)
    return (aesgcm.encrypt(nonce, data, aad),
            key,
            nonce
            )


def decrypt(key, cData, aad, nonce):
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, cData, aad)
