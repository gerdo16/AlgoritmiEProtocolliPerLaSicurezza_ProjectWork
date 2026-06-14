from typing import List
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature
import os



""" genera una chiave privata e una chiave pubblica"""
def generate_rsa_key_pair():
    sk = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    return sk, sk.public_key()

def rsa_encrypt(public_key, plaintext: bytes) -> bytes:
    """ cifra un messaggio con chiave pubblica RSA """
    ciphertext = public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

""" decifra un messaggio con chiave privata RSA """
def rsa_decrypt(private_key, ciphertext: bytes) -> bytes:
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext


def rsa_encrypt_chunks(public_key, plaintext: bytes, chunk_size: int = 190) -> List[bytes]:
    """
    Suddivide il plaintext in chunk e cifra ciascun chunk con RSA-OAEP.
    Ritorna una lista di crittogrammi (bytes).
    """
    encrypted_chunks = []
    # Itera sul plaintext a passi di 'chunk_size'
    for i in range(0, len(plaintext), chunk_size):
        chunk = plaintext[i : i + chunk_size]
        
        # Cifra il singolo blocco
        ciphertext = public_key.encrypt(
            chunk,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        encrypted_chunks.append(ciphertext)
        
    return encrypted_chunks


def rsa_decrypt_chunks(private_key, encrypted_chunks: List[bytes]) -> bytes:
    """
    Decifra una lista di crittogrammi RSA-OAEP e ricompone il plaintext originale.
    """
    decrypted_data = b''
    for i, chunk in enumerate(encrypted_chunks):
        try:
            plaintext_chunk = private_key.decrypt(
                chunk,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            decrypted_data += plaintext_chunk
        except Exception as e:
            # Cattura errori di decifratura (es. blocco alterato) e solleva eccezione chiara
            raise ValueError(f"Fallita la decifrazione del blocco {i}. Messaggio corrotto o manipolato.") from e
            
    return decrypted_data


""" firma un messaggio usando la chiave privata """
def sign(private_key, message: bytes) -> bytes:
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

""" verifica la firma di un messaggio usando la chiave pubblica """
def verifySign(public_key, message: bytes, signature: bytes) -> bool:
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False


if __name__ == "__main__":
    # test firma e verifica
    sk, pk = generate_rsa_key_pair()
    message = "Questo è un messaggio da firmare.".encode()
    signature = sign(sk, message)
    print( verifySign(pk, message, signature) )