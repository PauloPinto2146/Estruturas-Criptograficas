import asyncio
from crypto_utils import hkdf_sha256, sponge_aead_encrypt

class Client:
    def __init__(self):
        self.client_key = input("Chave do cliente: ")
        self.cypher_key = None
        self.client_nonce = None

    async def start_client(self):
        reader, writer = await asyncio.open_connection('127.0.0.1', 8888)

        # Recebe o client_id
        client_id = await reader.readline()
        client_id = client_id.decode().strip()
        print(f"Cliente ID recebido: {client_id}")

        # Recebe o salt
        salt = await reader.readline()
        salt = salt.strip()  # Remove o '\n'
        print(f"Salt recebido: {salt.decode()}")

        # Deriva a chave e nonce com HKDF
        derived_bytes = hkdf_sha256(salt, self.client_key)

        self.cypher_key = derived_bytes[:32] # 32 bytes para a chave -> 256 bits
        self.client_nonce = derived_bytes[32:] # 12 bytes para o nonce -> 96 bits
        print(f"Chave da cifra: {self.cypher_key.hex()}")
        print(f"Nonce do cliente: {self.client_nonce.hex()}")

        try:
            while True:
                message = await asyncio.get_event_loop().run_in_executor(None, input, "Digite a sua mensagem: ")
                if message.lower() == "sair":
                    break 

                chipher_message, tag = sponge_aead_encrypt(self.cypher_key,self.client_nonce,message.encode())
                print(f"Mensagem cifrada: {chipher_message.hex()}")
                print(f"Tag: {tag.hex()}")

                client_id_bytes = str(client_id).encode().ljust(4, b' ')  # Garantir 4 bytes fixos para o ID

                # Criar o pacote final: ID (4 bytes) + mensagem cifrada + tag (16 bytes)
                packet = client_id_bytes + chipher_message + tag

                writer.write(packet)
                await writer.drain()
                print("Mensagem enviada!")
        except Exception as e:
            print(f"Erro no cliente: {e}")
        finally:
            print("Sair...")
            writer.close()
            await writer.wait_closed()

    def run(self):
        asyncio.run(self.start_client())

if __name__ == "__main__":
    client = Client()
    client.run()
