import asyncio
import os
from crypto_utils import (
    generate_x25519_keypair, generate_ed25519_keypair, derive_shared_key,
    sign_message, verify_signature, encrypt_with_aead, x25519, ed25519
)

class Client:
    def __init__(self):
        self.private_key, self.public_key = generate_x25519_keypair()
        self.signing_key, self.verifying_key = generate_ed25519_keypair()
        self.server_verifying_key = None

    async def start_client(self):
        reader, writer = await asyncio.open_connection('127.0.0.1', 9001)

        # Recebe o client_id
        client_id = await reader.readline()
        client_id = client_id.decode().strip()
        print(f"Cliente ID recebido: {client_id}")

        # Envia a chave pública X25519 para o servidor
        writer.write(self.public_key.public_bytes_raw())
        await writer.drain()

        # Recebe a chave pública do servidor e deriva a chave compartilhada
        server_pubkey_bytes = await reader.read(32)
        server_pubkey = x25519.X25519PublicKey.from_public_bytes(server_pubkey_bytes)
        shared_key = derive_shared_key(self.private_key, server_pubkey)

        print(f"Chave derivada atraves da chave publica recebida do servidor: {shared_key.hex()}")

        # Recebe a chave de verificação Ed25519 do servidor
        server_verifying_key_bytes = await reader.readexactly(32)
        self.server_verifying_key = ed25519.Ed25519PublicKey.from_public_bytes(server_verifying_key_bytes)

        # Recebe a assinatura do servidor e valida
        signature = await reader.read(64)
        print(f"Assinatura recebida no cliente: {signature.hex()}")

        if not verify_signature(self.server_verifying_key, shared_key, signature):
            print("Assinatura inválida!")
            return

        print(f"Chave compartilhada estabelecida: {shared_key.hex()}")

        # Envia a chave de verificação Ed25519 para o servidor
        writer.write(self.verifying_key.public_bytes_raw())
        await writer.drain()
        
        try:
            while True:
                message = await asyncio.get_event_loop().run_in_executor(None, input, "Digite a sua mensagem: ")
                if message.lower() == 'sair':
                    break
                tweak = os.urandom(16)  # Gera um "tweak" aleatório de 16 bytes
                associated_data = str(client_id).encode().ljust(4, b' ')  # Dados associados para autenticação
                ciphertext = encrypt_with_aead(shared_key, tweak, message.encode(), associated_data)
                signature = sign_message(self.signing_key, ciphertext)
                print(f"Assinatura da mensagem: {signature.hex()}")
                print(f"Mensagem cifrada: {ciphertext.hex()}")
                print(f"Tweak: {tweak.hex()}")

                client_id_bytes = str(client_id).encode().ljust(4, b' ')  # Garantir 4 bytes fixos para o ID
                packet = client_id_bytes + tweak + ciphertext + signature

                writer.write(packet)
                await writer.drain()
                print("Mensagem enviada!")
        except Exception as e:
            print(f"Erro no cliente: {e}")
        finally:
            print("Sair...")
            writer.close()
            await writer.wait_closed()

if __name__ == "__main__":
    client = Client()
    asyncio.run(client.start_client())
