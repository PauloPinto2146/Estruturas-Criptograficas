import asyncio
from crypto_utils import hkdf_sha256, sponge_aead_decrypt, block_size

class Server:
    def __init__(self):
        self.clients = {}
        self.clientCounter = 1
        self.server_key = input("Chave do servidor: ")

    async def handle_client(self, reader, writer):
        client_id = self.clientCounter
        self.clientCounter += 1

        # Envia o client_id para o cliente
        writer.write(f"{client_id}\n".encode())
        await writer.drain()

        # Gera o salt para o cliente
        salt = b"salt_clientid_" + str(client_id).encode() + b"_messageid_" + str(0).encode()
        writer.write(salt + b"\n")  # Envia o salt para o cliente
        await writer.drain()

        derived_bytes = hkdf_sha256(salt, self.server_key)

        # Armazena o cliente na lista
        self.clients[int(client_id)] = {
            "writer": writer,
            "cypher_key": derived_bytes[:32], # 32 bytes para a chave -> 256 bits
            "nonce": derived_bytes[32:], # 12 bytes para o nonce -> 96 bits
            "messageCounter": 0
        }

        print(f"Cliente {client_id} conectado!")
        print(f"Chave da cifra gerada para o cliente {int(client_id)}: {self.clients[int(client_id)]['cypher_key'].hex()}")
        print(f"Nonce gerado para o cliente {int(client_id)}: {self.clients[int(client_id)]['nonce'].hex()}")

        try:
            while not reader.at_eof():
                id_bytes = await reader.readexactly(4)
                print("######## MENSAGEM RECEBIDA ########")
                client_id = id_bytes.decode().strip()
                print(f"ID do cliente: {int(client_id)}")
                data = await reader.read(1024)

                chipher_message = data[:-block_size]
                tag = data[-block_size:]
            
                print(f"Mensagem cifrada recebida: {chipher_message.hex()}")
                print(f"Tag recebida: {tag.hex()}")
                print(f"Chave da cifra do cliente: {self.clients[int(client_id)]['cypher_key'].hex()}")
                print(f"Nonce do cliente: {self.clients[int(client_id)]['nonce'].hex()}")

                decrypted_message  = sponge_aead_decrypt(self.clients[int(client_id)]['cypher_key'], self.clients[int(client_id)]['nonce'], chipher_message, tag)
                print(f"Mensagem decifrada: {decrypted_message.decode()}")
                print("######## FIM DE MENSAGEM ########")
                
                
                self.clients[int(client_id)]['messageCounter'] += 1
                # Gera o salt para o cliente
                salt = b"salt_clientid_" + str(client_id).encode() + b"_messageid_" + str(self.clients[int(client_id)]['messageCounter']).encode()
                writer.write(salt + b"\n")  # Envia o salt para o cliente
                await writer.drain()
                derived_bytes = hkdf_sha256(salt, self.server_key)
                self.clients[int(client_id)] = {
                    "writer": writer,
                    "cypher_key": self.clients[int(client_id)]['cypher_key'], # 32 bytes para a chave -> 256 bits
                    "nonce": derived_bytes[32:], # 12 bytes para o nonce -> 96 bits
                    "messageCounter": self.clients[int(client_id)]['messageCounter']
                }

        except Exception as e:
            print(f"Erro ao processar a mensagem do cliente {client_id}: {e}")
        finally:
            writer.close()
            await writer.wait_closed()
            del self.clients[int(client_id)]
            print(f"Cliente {client_id} saiu.")

    async def start_server(self):
        server = await asyncio.start_server(self.handle_client, '127.0.0.1', 9000)
        async with server:
            await server.serve_forever()

if __name__ == "__main__":
    server = Server()
    asyncio.run(server.start_server())