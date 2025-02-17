from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

def shake_256_xof(iv_key: bytes, length:int):
    """Gera um fluxo de bytes pseudo aleatório usando SHAKE-256"""
    print("iv_key: ",iv_key)
    shake = hashes.Hash(hashes.SHAKE256(64))  
    shake.update(iv_key)
    finalized_keystream = shake.finalize()[:length]
    print("finalized_keystream: ",finalized_keystream)
    return finalized_keystream

def encrypt_message(key: bytes, nonce: bytes, plaintext:bytes, associated_data: bytes):
    """Cifra e autentica a mensagem usando SHAKE-256 em modo XOF"""
    block_size = 16
    iv_key = nonce + key
    shake = hashes.Hash(hashes.SHAKE256(64))
    associated_blocks = [associated_data[i:i + block_size] for i in range (0,len(associated_data),block_size)]
    plaintext_blocks = [plaintext[i:i + block_size] for i in range (0,len(plaintext),block_size)]
    xor_result = bytearray()
    
    #Passo 1: Aplicar Hash ao initial vector concatenado com a key
    keystream = shake_256_xof(key,nonce,len(plaintext))

    #Passo 2: Encriptar dados associados à mensagem
    for block in associated_blocks:
        if block:
            print("BLOCK: ",block)
            print("iv_key: ",iv_key)
            print("BLOCO CIFRADO NA ITERAÇÃO: ",bytes(p ^ k for p,k in zip(block,iv_key)))
            xor_block = bytes(p ^ k for p,k in zip(block,iv_key))
            xor_result.extend(xor_block)
            print("xor_result: ",xor_result)
            iv_key = increment_bytes(iv_key)
        else:
            print("AVISO: BLOCO VAZIO ENCONTRADO")
    ciphertext = bytearray()
    #Passo 3: Encriptar mensagem (retirar o ciphertext)
    for block in plaintext_blocks:
        if block:
            print("BLOCK: ",block)
            print("iv_key: ",iv_key)
            print("BLOCO CIFRADO NA ITERAÇÃO: ",bytes(p ^ k for p,k in zip(block,iv_key)))
            xor_block = bytes(p ^ k for p,k in zip(block,iv_key))
            ciphertext.extend(xor_block)
            xor_result.extend(xor_block)
            print("xor_result: ",xor_result)
            iv_key = increment_bytes(iv_key)
        else:
            print("AVISO: BLOCO VAZIO ENCONTRADO")
    print("ciphertext: ",ciphertext)
    
    #Passo 4: Aplicar XOR com a chave, seguido de um Hash e outro XOR com a chave e obter a TAG
    xor_result = xor_result ^ key
    shake.update(xor_result)
    tag = xor_result ^ key
    
    print("Resultado final da cifração: \n",bytes(xor_result))
    print("tag: ",tag)
    #return bytes()

def increment_bytes(iv_key):
    iv_key_list = list(iv_key)
    for i in range(len(iv_key_list)-1,-1,-1):
        iv_key_list[i] += 1
        if iv_key_list[i]<256:
            break
        iv_key_list[i] = 0
    return bytes(iv_key_list)    

def decrypt_message(key: bytes, nonce: bytes, cifratext: bytes, tag: bytes):
    """Decifra a mensagem usando SHAKE-256"""
    shake_key = shake_256_xof(key)  # Deriva a chave novamente

    cifra = Cipher(algorithms.AES(shake_key), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cifra.decryptor()
    return decryptor.update(cifratext) + decryptor.finalize()


key = b"abcdefghijklmnop"
nonce = b"1234567890123456"
associated_data = b'This is some associated data that need to be processed in blocks.'

plaintext = b"This is the plaintext"

result = encrypt_message(key,nonce,plaintext,associated_data)

#TODO: TESTAR RESULTADOS AO FAZER DUAS CIFRAS PARA VER SE CIFRAS SÃO DIFERENTES O SUFICIENTE
#DECRYPT
#RETIRAR TAGS