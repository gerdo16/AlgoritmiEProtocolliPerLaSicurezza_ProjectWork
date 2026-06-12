from .utils import pack_fields, unpack_fields

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

""" genera una chiave privata e una chiave pubblica"""
def generate_rsa_key_pair():
    sk = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    return sk, sk.public_key()

""" crifra un messaggio con una chiave AES generata casualmente, e cifra la chiave AES con la chiave pubblica RSA """
def encrypt(public_key, plaintext: bytes) -> bytes:
    # chiave AES casuale
    aes_key = os.urandom(32)
    
    # nonce casuale per AES-GCM
    nonce = os.urandom(12)
    
    # cifrare il messaggio con AES-GCM
    aes = AESGCM(aes_key)
    ciphertext = aes.encrypt(nonce, plaintext, None)
    
    # cifrare la chiave AES con RSA
    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    return pack_fields(encrypted_key, nonce, ciphertext)
    

""" decifra una chiave AES cifrata con RSA, e usa la chiave AES per decifrare il messaggio """
def decrypt(private_key, data: bytes) -> bytes:
    # Ottengo la chiave AES cifrata, il nonce e il cyphertext
    enc_key, nonce, ciphertext = unpack_fields(data, 3)
    
    # chiave AES decifrata con RSA
    aes_key = private_key.decrypt(
        enc_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # plaintext decifrato con AES-GCM
    plaintext = AESGCM(aes_key).decrypt(nonce, ciphertext, None)

    return plaintext



""" firma un messaggio usando la chiave privata """
#def sign()
