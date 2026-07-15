# Prova de titularidade de carteiras autocustodiadas

**Projeto Final — Protocolo Bitcoin · 2026/01**
Autores: **Gustavo Nascimento Pavanelli** e **Marcel Capistrano Almeida Rodrigues**

Verificar de quem é a carteira externa para onde um cliente saca — a exigência que atinge o elo onde o crime organizado toca o sistema formal — já cabe dentro do Bitcoin, com o que ele sempre soube fazer: assinar mensagens. Este repositório mostra esse núcleo (prova de titularidade), propõe uma camada opcional que tentaria amarrá-lo a uma pessoa viva (*liveness*), e é honesto — inclusive em código — sobre onde o Bitcoin chega sozinho e onde não chega.

---

## 🔗 Entregas

| Peça | Link |
|---|---|
| 📄 **Artigo (página web / GitHub Pages)** | [https://pavanelligustavo.github.io/TrabalhoBitcoinProjetoFinal/](https://pavanelligustavo.github.io/TrabalhoBitcoinProjetoFinal/) |
| 🎥 **Apresentação (vídeo, 5–10 min)** | [Titularidade de carteiras autocustodiadas - uma visão teórica](https://youtu.be/2tQZjZv-PEw) |

---

## 📁 Estrutura do repositório

```
.
├── index.html                          # Artigo (servido pelo GitHub Pages)
└── README.md
```

---

## 🧩 O problema, em uma frase

A Travel Rule (FATF R.16, revisada em 2025) e a Resolução BCB 521 (vigência 2026) obrigam a corretora a **verificar a titularidade** da carteira autocustodiada de destino. Elas **não** exigem biometria nem vigilância da população — a obrigação recai sobre a corretora, no ponto de contato com o sistema formal. A questão técnica: os métodos atuais provam o **controle de uma chave**, não a **identidade de quem opera**.

## 💡 A solução

O núcleo é nativo do Bitcoin: **assinar uma mensagem** com a chave privada do endereço prova o controle, sem revelar a chave e sem gastar nada (é o que o AOPP industrializou, e o que o **BIP-322** generaliza para segwit/taproot). A camada opcional tenta fechar o buraco "assinatura ≠ pessoa" com uma prova de vida *off-chain* vinculada por uma mensagem de compromisso:

```
m = H( nonce ‖ hash(tx) ‖ id_sessão )
```

## 🔍 Ethereum × Bitcoin (o que precisaria no Bitcoin)

| Peça | Bitcoin | Ethereum |
|---|---|---|
| Provar controle da chave (assinar `m`) | ✅ nativo (BIP-322) | ✅ |
| Carimbar um hash da atestação | ✅ `OP_RETURN` / OpenTimestamps | ✅ |
| Verificar a atestação e **recusar a tx sem ela** | ❌ Script não introspecta dados externos | ✅ contrato + ERC-4337 |
| Verificar prova ZK **on-chain** | ❌ (só off-chain / pesquisa: BitVM) | ✅ |

O núcleo obrigatório é Bitcoin nativo; a imposição da atestação na cadeia é o "contrato que só o Ethereum tem".

---

## 📚 Referências

As fontes completas (operações Exchange e Carbono Oculto, FATF R.16/2025, Resoluções BCB 519–521, AOPP, BIP-322, LGPD/GDPR) estão listadas ao final do [artigo](./index.html).
