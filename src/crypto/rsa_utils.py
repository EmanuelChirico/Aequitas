from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.asymmetric import rsa

from config import LAMBDA

# Funzione di generazione delle chiavi
def gen_rsa_keypair(key_size: int = LAMBDA):
    return rsa.generate_private_key(public_exponent=65537, key_size=key_size)



# RSA-OAEP: funzioni di encrypt e decrypt                                                         

def oaep_encrypt(public_key, plaintext: bytes) -> bytes:
    # Cifra plaintext con RSA-OAEP
    return public_key.encrypt(
        plaintext,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def oaep_decrypt(private_key, ciphertext: bytes) -> bytes:
    #Decifra con RSA-OAEP.
    
    return private_key.decrypt(
        ciphertext,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


# RSA-PSS: funzioni di hash and sign e di verify

def hash_and_sign(private_key, message: bytes) -> bytes:
    #Firma messaggio con RSA-PSS 
    return private_key.sign(
        message,
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )


def hash_and_verify(public_key, message: bytes, sigma: bytes) -> bool:
    #Verifica la firma RSA-PSS. Restituisce False se la firma non è valida
    try:
        public_key.verify(
            sigma,
            message,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False
