import asyncio
from crypto_utils import decrypt_message

key_receiver = b'minha_chave'

async def handle_client(reader, writer):
    """Recebe mensagens criptografadas e decifra-as"""
    print("Cliente conectado!")
    try:
        while True
            data = await reader.read(1024)
            if not data:
                print("Cliente desconectado.")
                break

            nonce, ciphertext, tag = data[:16], data[16:-16], data[-16:]
            print("Defini nonce, ciphertext, tag")

            message = decrypt_message(key_receiver, nonce, ciphertext, tag)
            print(f"Mensagem Recebida e decifrada: {message.decode()}")

    except Exception as e:
        print(e)
    finally:
        writer.close()
        await writer.wait_closed()
        print("Conexão com o cliente encerrada.")

async def start_server():
    """Inicia o servidor"""
    print("Servidor iniciado!")
    server = await asyncio.start_server(handle_client, '127.0.0.1', 8000)
    async with server:
        await server.serve_forever()

print("Iniciando servidor...")
asyncio.run(start_server())