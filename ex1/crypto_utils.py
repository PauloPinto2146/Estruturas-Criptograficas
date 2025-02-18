from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

associated_data = b'This is some associated data that need to be processed in blocks.'
block_size = 16

# Docs: https://cryptography.io/en/latest/hazmat/primitives/key-derivation-functions/
def hkdf_sha256(salt: bytes, key: bytes) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=44, # 32 bytes para a chave e 12 bytes para o nonce
        salt=salt, #Randomizes the KDF’s output.
        info=b'',
    )
    derived_bytes = hkdf.derive(key.encode())
    return derived_bytes


def sponge_aead_encrypt(key: bytes, nonce: bytes, plaintext: str):
    """Cifra a mensagem usando SHAKE-256"""

    iv_key = nonce + key   
    shake = hashes.Hash(hashes.SHAKE256(64))

    # Passo 1: Iniciar com IV || Key e aplicar o shake
    shake.update(iv_key)

    # Passo 2: Absorver os dados associados 
    for i in range(0, len(associated_data), block_size):
        shake.update(associated_data[i:i + block_size])

    #Passo 3: Processar a mensagem e fazer squeeze do ciphertext
    ciphertext = b""
    for i in range(0, len(plaintext), block_size):
        block = plaintext[i:i + block_size]
        keystream = shake.copy().finalize()[:len(block)]
        ciphertext += bytes(a ^ b for a, b in zip(block, keystream))
        #print(f"[CLIENTE] Absorvendo bloco: {block.hex()}")
        shake.update(block)  # Continua absorvendo

    #Passo 4: Finaliza e gera a Tag
    state = shake.copy().finalize()[:block_size]  # Obtém estado interno atual

    #print(f"[CLIENTE] Estado após primeiro XOR: {state.hex()}")
    # XOR com K
    state = bytes(a ^ b for a, b in zip(state, key))
    # Faz update com esse novo estado
    shake.update(state)
    # Aplica um segundo XOR com K
    state = bytes(a ^ b for a, b in zip(state, key))

    # Finaliza tag
    #print(f"[CLIENTE] Estado final antes da tag: {shake.copy().finalize().hex()}")
    tag = shake.finalize()[:block_size]

    return ciphertext, tag

def sponge_aead_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes):
    """Decifra a mensagem usando SHAKE-256"""

    iv_key = nonce + key
    shake = hashes.Hash(hashes.SHAKE256(64))
    
    # Passo 1: Iniciar com IV || Key e aplicar o shake
    shake.update(iv_key)

    # Passo 2: Absorver os dados associados 
    for i in range(0, len(associated_data), block_size):
        shake.update(associated_data[i:i + block_size])

    # Passo 3: Processar o ciphertext e recuperar o plaintext
    plaintext = b""
    for i in range(0, len(ciphertext), block_size):
        block = ciphertext[i:i + block_size]
        keystream = shake.copy().finalize()[:len(block)]
        plaintext += bytes(a ^ b for a, b in zip(block, keystream))
        #print(f"[SERVIDOR] Absorvendo bloco: {block.hex()}")
        #shake.update(block)  # Continua absorvendo
        shake.update(plaintext[i:i + block_size])  # Absorver o plaintext correto

    # Passo 4: Recalcular a Tag para verificar a integridade
    state = shake.copy().finalize()[:block_size]  # Obtém estado interno atual

    #print(f"[SERVIDOR] Estado após primeiro XOR: {state.hex()}")

    # XOR com K
    state = bytes(a ^ b for a, b in zip(state, key))
    # Faz update com esse novo estado
    shake.update(state)
    # Aplica um segundo XOR com K
    state = bytes(a ^ b for a, b in zip(state, key))
    
    # Finaliza e gera a tag para verificação
    #print(f"[SERVIDOR] Estado final antes da tag: {shake.copy().finalize().hex()}")

    computed_tag = shake.finalize()[:block_size]

    #print(f"Tag computada: {computed_tag.hex()}")
    #print(f"Tag recebida: {tag.hex()}")
    #print(f"Plaintext: {plaintext.decode()}")

    # Verifica se a tag é igual
    if computed_tag != tag:
        raise ValueError("Autenticação falhou! O ciphertext foi alterado ou a chave está errada.")

    return plaintext