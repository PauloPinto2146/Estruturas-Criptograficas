import asyncio
from crypto_utils import (
    generate_x25519_keypair, generate_ed25519_keypair, ign,
    sign_message, verify_signature, decrypt_with_aead, x25519, ed25519, serialization
)

class Server:
    def __init__(self):
        self.clients = {}
        self.clientCounter = 1
        self.private_key, self.public_key = generate_x25519_keypair()
        self.signing_key, self.verifying_key = generate_ed25519_keypair()

    async def handle_client(self, reader, writer):
        client_id = self.clientCounter
        self.clientCounter += 1

         # Envia o client_id para o cliente
        writer.write(f"{client_id}\n".encode())
        await writer.drain()

        # Recebe a chave pública do cliente
        client_pubkey_bytes = await reader.read(32)
        client_pubkey = x25519.X25519PublicKey.from_public_bytes(client_pubkey_bytes)

        # Deriva a chave compartilhada
        shared_key = derive_shared_key(self.private_key, client_pubkey)
        print(f"Chave derivada atraves da chave publica recebida do cliente: {shared_key.hex()}")

        # Envia a chave pública X25519 para o cliente
        writer.write(self.public_key.public_bytes_raw())
        await writer.drain()

        # Envia a chave de verificação Ed25519 para o cliente
        writer.write(self.verifying_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        ))
        await writer.drain()

        # Assina a chave compartilhada
        signature = sign_message(self.signing_key, shared_key)
        print(f"Assinatura da chave compartilhada: {signature.hex()}")

        # Envia a assinatura para o cliente
        writer.write(signature)
        await writer.drain()

        print(f"Chave compartilhada estabelecida: {shared_key.hex()}")

        #Recebe a chave de verificação do cliente
        client_verifying_key_bytes = await reader.readexactly(32)
        client_verifying_key = ed25519.Ed25519PublicKey.from_public_bytes(client_verifying_key_bytes)
        
        # Armazena o cliente na lista
        self.clients[int(client_id)] = {
            "writer": writer,
            "shared_key": shared_key,
            "client_verifying_key": client_verifying_key
        }
        
        try:
            while not reader.at_eof():
                id_bytes = await reader.readexactly(4)
                print("######## MENSAGEM RECEBIDA ########")
                client_id = id_bytes.decode().strip()
                print(f"ID do cliente: {int(client_id)}")
                data = await reader.read(1024)
               
                #Separar tweak, ciphertext e assinatura
                tweak = data[:16]
                ciphertext = data[16:-64]
                signature = data[-64:]

                print(f"Tweak: {tweak.hex()}")
                print(f"Mensagem cifrada: {ciphertext.hex()}")
                print(f"Assinatura: {signature.hex()}")
           
                if not verify_signature(self.clients[int(client_id)]['client_verifying_key'], ciphertext, signature):
                    print("Erro: Assinatura inválida! Mensagem rejeitada.")
                    continue
                
                associated_data = str(client_id).encode().ljust(4, b' ')

                try:
                    plaintext = decrypt_with_aead(self.clients[int(client_id)]['shared_key'], tweak, ciphertext, associated_data)
                    print(f"Mensagem recebida e verificada: {plaintext.decode()}")
                except Exception as e:
                    print(f"Erro ao decifrar a mensagem: {e}")
                    continue
                print("######## FIM DE MENSAGEM ########")
        except Exception as e:
            print(f"Erro ao processar a mensagem do cliente {client_id}: {e}")
        finally:
            writer.close()
            await writer.wait_closed()
            del self.clients[int(client_id)]
            print(f"Cliente {client_id} saiu.")

    async def start_server(self):
        server = await asyncio.start_server(self.handle_client, '127.0.0.1', 8888)
        async with server:
            await server.serve_forever()

if __name__ == "__main__":
    server = Server()
    asyncio.run(server.start_server())
