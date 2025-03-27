
# TP1
1. Use a package cryptography    para  criar um comunicação privada assíncrona entre um agente Emitter e um agente Receiver que cubra os seguintes aspectos:
    1. Comunicação cliente-servidor que use o package python `asyncio`.
    2. Usar como cifra AEAD   o “hash” SHAKE-256  em modo XOFHash
    3. As chaves de cifra  e  os “nounces” são gerados por um gerador KDF . As diferentes chaves para inicialização KDF  são inputs do emissor e do receptor.


2. Use o “package” cryptography para
    1. Implementar uma AEAD com “Tweakable Block Ciphers” conforme está descrito na última secção do texto +Capítulo 1: Primitivas Criptográficas Básicas.  A cifra por blocos primitiva, usada para gerar a “tweakable block cipher”, é o AES-128.
    2. Use esta cifra para construir um canal privado de informação assíncrona com acordo de chaves feito com “X25519 key exchange” e “Ed25519 Signing&Verification” para autenticação  dos agentes.  Deve incluir a confirmação da chave acordada.
