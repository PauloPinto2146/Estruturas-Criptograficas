import asyncio
from crypto_utils import encrypt_message

# Defina a chave do emissor (deve ser a mesma usada no servidor)
key_emitter = b'minha_chave'

async def send_message(writer):
    """Envia uma mensagem criptografada para o servidor"""
    message = input("Digite a mensagem para enviar ao servidor: ")
    
    # Criptografa a mensagem (a mensagem já é codificada em bytes antes de ser passada para a função)
    nonce, ciphertext, tag = encrypt_message(key_emitter, message)

    writer.write(nonce + ciphertext + tag)
    await writer.drain()

    print("Mensagem Enviada!")
    writer.close()

async def start_client():
    """Cliente que envia mensagens criptografadas"""
    print("Cliente inicializado!")
    reader, writer = await asyncio.open_connection('127.0.0.1', 8000)
    print("Cliente conectado")
    print("     reader: ", reader)
    print("     writer: ", writer)

    await send_message(writer)

# Executa o cliente
print("Iniciando cliente...")
asyncio.run(start_client())