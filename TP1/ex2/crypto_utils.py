from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import padding
import os

def tweakable_aes_encrypt(key: bytes, tweak: bytes, plaintext: bytes) -> bytes:
    """Aplica AES-128 no modo ECB com tweak XOR na chave."""
    assert len(key) == 16, "A chave deve ter 16 bytes (AES-128)."
    assert len(tweak) == 16, "O tweak deve ter 16 bytes."
    
    tweaked_key = bytes(a ^ b for a, b in zip(key, tweak))
    cipher = Cipher(algorithms.AES(tweaked_key), modes.ECB())
    encryptor = cipher.encryptor()

    # Adiciona padding caso a messagem não seja múltipla de 16 bytes
    padder = padding.PKCS7(128).padder() # 128 bits = 16 bytes * 8
    padded_plaintext = padder.update(plaintext) + padder.finalize()

    return encryptor.update(padded_plaintext) + encryptor.finalize()

def tweakable_aes_decrypt(key: bytes, tweak: bytes, ciphertext: bytes) -> bytes:
    """Decifra AES-128 no modo ECB com tweak XOR na chave."""
    assert len(key) == 16, "A chave deve ter 16 bytes (AES-128)."
    assert len(tweak) == 16, "O tweak deve ter 16 bytes."
    
    tweaked_key = bytes(a ^ b for a, b in zip(key, tweak))
    cipher = Cipher(algorithms.AES(tweaked_key), modes.ECB())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Remove padding
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    return plaintext

def encrypt_with_aead(key, tweak, plaintext, associated_data):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(associated_data)
    associated_hash = digest.finalize()
    
    extended_plaintext = associated_hash + plaintext
    ciphertext = tweakable_aes_encrypt(key, tweak, extended_plaintext)
    
    return ciphertext

def decrypt_with_aead(key, tweak, ciphertext, associated_data):
    decrypted = tweakable_aes_decrypt(key, tweak, ciphertext)
    
    stored_hash = decrypted[:32]
    plaintext = decrypted[32:]
    
    digest = hashes.Hash(hashes.SHA256())
    digest.update(associated_data)
    expected_hash = digest.finalize()
    
    if stored_hash != expected_hash:
        raise ValueError("Dados associados não correspondem! Texto pode ter sido adulterado.")
    
    return plaintext

def generate_x25519_keypair():
    """Gera um par de chaves X25519."""
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key

def generate_ed25519_keypair():
    """Gera um par de chaves Ed25519 para assinatura."""
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key

def derive_shared_key(private_key, peer_public_key):
    """Deriva uma chave compartilhada usando X25519."""
    shared_secret = private_key.exchange(peer_public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=16,  # Chave de 16 bytes para AES-128
        salt=None,
        info=b'handshake data'
    ).derive(shared_secret)
    return derived_key

def sign_message(private_key, message: bytes) -> bytes:
    """Assina uma mensagem usando Ed25519."""
    return private_key.sign(message)

def verify_signature(public_key, message: bytes, signature: bytes):
    """Verifica a assinatura de uma mensagem com Ed25519."""
    try:
        public_key.verify(signature, message)
        return True
    except:
        return False