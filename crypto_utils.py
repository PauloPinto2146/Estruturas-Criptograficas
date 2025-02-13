from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

def shake_256_xof(key: bytes):
    """Aplica SHAKE-256 em modo XOFHash para gerar uma chave AES válida (32 bytes)"""
    digest = hashes.Hash(hashes.SHAKE256(32), backend=default_backend())  
    digest.update(key)  # Atualiza o hash com a chave
    return digest.finalize()  # Retorna os bytes gerados

def encrypt_message(key: bytes, message: str):
    """Cifra a mensagem usando SHAKE-256 e um nonce"""
    nonce = derive_nonce(key)  # Deriva um nonce determinístico
    shake_key = shake_256_xof(key)  # Chave criada pelo SHAKE-256

    cifra = Cipher(algorithms.AES(shake_key), modes.GCM(nonce), backend=default_backend())
    encryptor = cifra.encryptor()
    cifratext = encryptor.update(message.encode()) + encryptor.finalize()
    
    return nonce, cifratext, encryptor.tag


def decrypt_message(key: bytes, nonce: bytes, cifratext: bytes, tag: bytes):
    """Decifra a mensagem usando SHAKE-256"""
    shake_key = shake_256_xof(key)  # Deriva a chave novamente

    cifra = Cipher(algorithms.AES(shake_key), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cifra.decryptor()
    return decryptor.update(cifratext) + decryptor.finalize()

def derive_nonce(key: bytes):
    """Deriva um nonce determinístico a partir da chave usando SHAKE-256"""
    digest = hashes.Hash(hashes.SHAKE256(16), backend=default_backend())  
    digest.update(key)  
    return digest.finalize()