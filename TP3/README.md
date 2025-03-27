
TP3

Este trabalho deve ser implementado tanto quanto possível em Sagemath. O objectivo do trabalho é construir protótipos de protocolos de conhecimento zero (ZK)  que usem  “Oblivious Transfer”  (OT),  passando por protocolos  “Vectorial Oblivious Linear Evaluation”  (VOLE)  e eventualmente protocolos de “Multi-Party Computation” (MPC), ou  “Garbled Circuits” (GC).


1. Pretende-se um protótipo protocolo $$\,{N\choose{N-1}}\,$$-OT, usando a abordagem $$\,\mathsf{LPN}\,$$ “Learning Parity with Noise” +Capítulo 6d:  Oblivious Linear Evaluation para mensagens de $$\,n\,$$ bytes (i.e. $$\,8\times n\,$$bits) que possa ser convertido para mensagens $$\,m\in \mathbb{F}_p^n\,$$ (vetores de $$\,n\,$$componentes no corpo finito  $$\,\mathbb{F}_p\,$$). Para isso
    1. Implemente um protótipo do protocolo $$\,\mathsf{LPN}$$ $$\,{N\choose{N-1}}$$-OT  para mensagens de $$\,n\,$$ bytes (i.e. $$\,8\times n\,$$bits). Ver +Capítulo 6d:  Oblivious Linear Evaluation .
    2. Codificando os elementos de um corpo primo $$\;\mathbb{F}_p\;$$ em “arrays” de “bytes” , converta a solução anterior num protocolo $$\,{N\choose{N-1}}$$-OT em que as mensagens são  vetores $$\,\mathbb{F}_p^\ell\,$$.


2. Usando o protocolo  OT construído na questão anterior
    1. Implemente o protocolo $$\,\mathsf{sVOLE}\;$$ (“subset vectorial oblivious linear evaluation”)
    2. Usando $$\,\mathsf{sVOLE}\,$$   implemente um protótipo de um protocolo  ZK-sVOLE usando equações polinomiais do 2º grau aleatoriamente geradas.


3. Pretende-se um protocolo ZK  baseados na computação sobre circuitos que usem “oblivious transfer” . Para tal
    1. Implemente um algoritmo que, a partir de uma “seed” $$\,s\in\{0,1\}^\lambda\,$$ aleatoriamente gerada e de um XOF,  construa um circuito booleano $$\,n\times 1\,$$ de dimensão $$\,\mathsf{poly}(n)\,$$. 
    2. Implemente um dos seguintes protocolos com este circuito
        1. O protocolo o protocolo ZK não interactivo de dois passos baseado no modelo “MPC-in-the-Head” com “Oblivious Transfer” (MPCitH-OT)  (ver a última secção do   +Capítulo 6c: Computação Cooperativa ).
        2. O protocolo de conhecimento zero com “garbled circuits” e  “oblivious transfer”  (ZK-GC-OT),  ver última secção do +Capítulo 6e: “Garbled Circuits” .
