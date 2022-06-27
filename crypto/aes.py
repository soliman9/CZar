from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from os import urandom


def encrypt(self, data, aad):
    key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(key)
    nonce = urandom(12)
    return aesgcm.encrypt(nonce, data, aad)


def decrypt(self, key, cData, aad, nonce):
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, cData, aad)
