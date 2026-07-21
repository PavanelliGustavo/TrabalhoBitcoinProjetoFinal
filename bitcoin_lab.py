#!/usr/bin/env python3
# =============================================================================
#  bitcoin_lab.py  -  Laboratorio de transacoes Bitcoin, do zero.
#
#  ZERO dependencias externas. ECDSA (secp256k1) implementado a mao.
#  Nada aqui toca a rede. Sao apenas bytes construidos na sua maquina.
#
#  Uso:  python3 bitcoin_lab.py
# =============================================================================

import hashlib
import hmac

# -----------------------------------------------------------------------------
# 0. PRIMITIVAS DE HASH
# -----------------------------------------------------------------------------

def sha256(b):      return hashlib.sha256(b).digest()
def hash256(b):     return sha256(sha256(b))                 # SHA256 duplo
def hash160(b):     return hashlib.new("ripemd160", sha256(b)).digest()

# -----------------------------------------------------------------------------
# 1. SECP256K1 + ECDSA  (implementado do zero, para nao haver caixa-preta)
# -----------------------------------------------------------------------------

P  = 2**256 - 2**32 - 977
N  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G  = (Gx, Gy)

def point_add(a, b):
    if a is None: return b
    if b is None: return a
    if a[0] == b[0] and (a[1] + b[1]) % P == 0: return None
    if a == b:
        lam = (3 * a[0] * a[0]) * pow(2 * a[1], P - 2, P) % P
    else:
        lam = (b[1] - a[1]) * pow(b[0] - a[0], P - 2, P) % P
    x = (lam * lam - a[0] - b[0]) % P
    y = (lam * (a[0] - x) - a[1]) % P
    return (x, y)

def point_mul(k, pt=G):
    r = None
    while k:
        if k & 1: r = point_add(r, pt)
        pt = point_add(pt, pt)
        k >>= 1
    return r

def pubkey_compressed(priv):
    """Chave publica em formato comprimido: 33 bytes (prefixo de paridade + X)."""
    x, y = point_mul(priv)
    return (b"\x02" if y % 2 == 0 else b"\x03") + x.to_bytes(32, "big")

def rfc6979_k(priv, z):
    """Nonce deterministico (RFC 6979). Nonce repetido = chave privada vazada."""
    v = b"\x01" * 32
    k = b"\x00" * 32
    zb = z.to_bytes(32, "big")
    pb = priv.to_bytes(32, "big")
    k = hmac.new(k, v + b"\x00" + pb + zb, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v + b"\x01" + pb + zb, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    while True:
        v = hmac.new(k, v, hashlib.sha256).digest()
        cand = int.from_bytes(v, "big")
        if 1 <= cand < N:
            return cand
        k = hmac.new(k, v + b"\x00", hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()

def ecdsa_sign(priv, z):
    k = rfc6979_k(priv, z)
    r = point_mul(k)[0] % N
    s = (pow(k, N - 2, N) * (z + r * priv)) % N
    if s > N // 2:          # low-s obrigatorio (BIP-62): evita maleabilidade
        s = N - s
    return r, s

def ecdsa_verify(pub_point, z, r, s):
    w  = pow(s, N - 2, N)
    p1 = point_mul((z * w) % N)
    p2 = point_mul((r * w) % N, pub_point)
    return point_add(p1, p2)[0] % N == r

def der_encode(r, s):
    """Assinatura no formato DER, como o consenso do Bitcoin exige."""
    def enc(v):
        b = v.to_bytes(32, "big").lstrip(b"\x00")
        if b[0] & 0x80: b = b"\x00" + b     # DER e' com sinal: evita virar negativo
        return b"\x02" + bytes([len(b)]) + b
    body = enc(r) + enc(s)
    return b"\x30" + bytes([len(body)]) + body

# -----------------------------------------------------------------------------
# 2. SERIALIZACAO
# -----------------------------------------------------------------------------

def varint(i):
    if i < 0xfd:        return bytes([i])
    if i <= 0xffff:     return b"\xfd" + i.to_bytes(2, "little")
    if i <= 0xffffffff: return b"\xfe" + i.to_bytes(4, "little")
    return b"\xff" + i.to_bytes(8, "little")

def push(data):
    """Empurra dados na pilha do Script (para tamanhos pequenos, o byte E' o tamanho)."""
    assert len(data) < 76
    return bytes([len(data)]) + data

def p2pkh_script(h160):
    # OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
    return b"\x76\xa9" + push(h160) + b"\x88\xac"

def serialize_tx(version, inputs, outputs, locktime):
    """
    inputs : lista de (txid_display_hex, vout, scriptSig_bytes, sequence)
    outputs: lista de (satoshis, scriptPubKey_bytes)
    """
    out = version.to_bytes(4, "little")
    out += varint(len(inputs))
    for txid_hex, vout, script_sig, seq in inputs:
        # ATENCAO: o txid vai INVERTIDO (internal byte order)
        out += bytes.fromhex(txid_hex)[::-1]
        out += vout.to_bytes(4, "little")
        out += varint(len(script_sig)) + script_sig
        out += seq.to_bytes(4, "little")
    out += varint(len(outputs))
    for sats, spk in outputs:
        out += sats.to_bytes(8, "little")
        out += varint(len(spk)) + spk
    out += locktime.to_bytes(4, "little")
    return out

# -----------------------------------------------------------------------------
# 3. VALORES FICTICIOS DO LABORATORIO
# -----------------------------------------------------------------------------

PRIV = 0xC0FFEE00000000000000000000000000000000000000000000000000DECAFBAD
PUB  = pubkey_compressed(PRIV)
MY_H160 = hash160(PUB)

# UTXO ficticio que vamos gastar (inventado; no regtest viria de `listunspent`)
PREV_TXID = "9f2c1d4b7e8a3056c1b2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4"
PREV_VOUT = 0
PREV_VALUE = 100_000_000                       # 1.00000000 BTC = 100 milhoes de sats
PREV_SPK  = p2pkh_script(MY_H160)              # o UTXO estava travado para a nossa chave

DEST_H160 = hash160(b"endereco-de-destino-ficticio")
SEND      = 70_000_000                         # 0.7 BTC para o destinatario
CHANGE    = 29_990_000                         # 0.2999 BTC de troco de volta para nos
FEE       = PREV_VALUE - SEND - CHANGE         # a TAXA nao e' um campo: e' a sobra

SIGHASH_ALL = 1

# -----------------------------------------------------------------------------
# 4. NIVEL 2 - MONTAR OS BYTES
# -----------------------------------------------------------------------------

print("=" * 74)
print("PASSO 1  -  Chaves e o UTXO que vamos gastar")
print("=" * 74)
print(f"chave privada   : {PRIV:064x}")
print(f"chave publica   : {PUB.hex()}")
print(f"hash160 (=nosso 'endereco' bruto): {MY_H160.hex()}")
print()
print(f"UTXO de entrada : {PREV_TXID}:{PREV_VOUT}")
print(f"  valor         : {PREV_VALUE:,} sats")
print(f"  scriptPubKey  : {PREV_SPK.hex()}")
print()
print(f"Vamos enviar    : {SEND:,} sats")
print(f"Troco p/ nos    : {CHANGE:,} sats")
print(f"TAXA (a sobra)  : {FEE:,} sats   <- ninguem escreve isso; e' inputs - outputs")

outputs = [
    (SEND,   p2pkh_script(DEST_H160)),
    (CHANGE, p2pkh_script(MY_H160)),
]

# --- 4a. Transacao NAO assinada: scriptSig vazio
unsigned = serialize_tx(
    version=2,
    inputs=[(PREV_TXID, PREV_VOUT, b"", 0xffffffff)],
    outputs=outputs,
    locktime=0,
)

print()
print("=" * 74)
print("PASSO 2  -  Transacao crua, ainda SEM assinatura")
print("=" * 74)
print(unsigned.hex())
print()
print("Dissecando os bytes:")
print(f"  02000000                          versao = 2 (little-endian)")
print(f"  01                                1 input")
print(f"  {bytes.fromhex(PREV_TXID)[::-1].hex()}")
print(f"                                    ^ txid INVERTIDO")
print(f"  00000000                          vout = 0")
print(f"  00                                scriptSig VAZIO (ainda nao assinamos)")
print(f"  ffffffff                          sequence")
print(f"  02                                2 outputs")
print(f"  {SEND.to_bytes(8,'little').hex()}                  valor = {SEND:,} sats (LE)")
print(f"  19 {p2pkh_script(DEST_H160).hex()}   scriptPubKey do destino")
print(f"  {CHANGE.to_bytes(8,'little').hex()}                  valor = {CHANGE:,} sats (troco)")
print(f"  19 {p2pkh_script(MY_H160).hex()}   scriptPubKey do troco")
print(f"  00000000                          locktime")

# -----------------------------------------------------------------------------
# 5. O SIGHASH  -  o que realmente e' assinado
# -----------------------------------------------------------------------------

# Regra legada: no input que estamos assinando, o scriptSig e' TEMPORARIAMENTE
# substituido pelo scriptPubKey do UTXO sendo gasto. Depois anexa-se o tipo de
# sighash em 4 bytes. O hash256 disso e' o numero 'z' que assinamos.
preimage = serialize_tx(
    version=2,
    inputs=[(PREV_TXID, PREV_VOUT, PREV_SPK, 0xffffffff)],   # <- substituido!
    outputs=outputs,
    locktime=0,
) + SIGHASH_ALL.to_bytes(4, "little")

z = int.from_bytes(hash256(preimage), "big")

print()
print("=" * 74)
print("PASSO 3  -  O sighash: o numero que a chave privada realmente assina")
print("=" * 74)
print("Nao se assina 'a transacao'. Assina-se o hash de uma VERSAO MODIFICADA dela.")
print(f"pre-imagem ({len(preimage)} bytes, termina em 01000000 = SIGHASH_ALL):")
print(f"  ...{preimage[-40:].hex()}")
print(f"z = hash256(pre-imagem) = {z:064x}")

# -----------------------------------------------------------------------------
# 6. ASSINAR E MONTAR O scriptSig
# -----------------------------------------------------------------------------

r, s = ecdsa_sign(PRIV, z)
sig_der = der_encode(r, s) + bytes([SIGHASH_ALL])   # DER + 1 byte de sighash type
script_sig = push(sig_der) + push(PUB)             # <assinatura> <chave publica>

signed = serialize_tx(
    version=2,
    inputs=[(PREV_TXID, PREV_VOUT, script_sig, 0xffffffff)],
    outputs=outputs,
    locktime=0,
)
txid = hash256(signed)[::-1].hex()

ok = ecdsa_verify(point_mul(PRIV), z, r, s)

print()
print("=" * 74)
print("PASSO 4  -  Assinatura e transacao final")
print("=" * 74)
print(f"r = {r:064x}")
print(f"s = {s:064x}   (low-s: s < n/2)")
print(f"assinatura DER + sighash byte ({len(sig_der)} bytes):")
print(f"  {sig_der.hex()}")
print(f"verificacao ECDSA da propria assinatura: {'VALIDA' if ok else 'INVALIDA'}")
print()
print(f"TXID (hash256 da tx, invertido): {txid}")
print()
print("TRANSACAO FINAL ASSINADA (isto e' o que se transmite):")
print(signed.hex())
print()
print(f"tamanho: {len(signed)} bytes   |   taxa: {FEE:,} sats"
      f"   |   taxa/byte: {FEE/len(signed):.1f} sat/vB")

# -----------------------------------------------------------------------------
# 7. NIVEL 3 - O ENVELOPE P2P (a mensagem 'tx' que trafega na porta 8333)
# -----------------------------------------------------------------------------

MAGIC = {"mainnet": bytes.fromhex("f9beb4d9"),
         "regtest": bytes.fromhex("fabfb5da"),
         "signet":  bytes.fromhex("0a03cf40")}

def p2p_message(command, payload, network="regtest"):
    cmd = command.encode().ljust(12, b"\x00")            # nome do comando, 12 bytes
    length = len(payload).to_bytes(4, "little")
    checksum = hash256(payload)[:4]                      # 4 primeiros bytes do hash256
    return MAGIC[network] + cmd + length + checksum + payload

msg = p2p_message("tx", signed, "regtest")

print()
print("=" * 74)
print("PASSO 5  -  Nivel 3: o envelope P2P (mensagem 'tx')")
print("=" * 74)
print("Transmitir = abrir um socket TCP no no e mandar estes bytes. Nada mais.")
print(f"  magic    : {msg[0:4].hex()}       (regtest)")
print(f"  command  : {msg[4:16].hex()}   ('tx' + zeros)")
print(f"  length   : {msg[16:20].hex()}       ({len(signed)} bytes de payload)")
print(f"  checksum : {msg[20:24].hex()}")
print(f"  payload  : a transacao inteira")
print()
print(f"mensagem completa ({len(msg)} bytes):")
print(f"  {msg.hex()}")
print()
print("No Nivel 1, voce entregaria a mesma transacao assim:")
print(f"  bitcoin-cli -regtest sendrawtransaction {signed.hex()[:32]}...")

# -----------------------------------------------------------------------------
# 8. ASSINAR UMA *MENSAGEM* - por que e' outra coisa
# -----------------------------------------------------------------------------

MSG_MAGIC = b"\x18Bitcoin Signed Message:\n"   # 0x18 = 24 = tamanho da string

def sign_message(priv, texto):
    payload = texto.encode()
    # O prefixo magico e' o que impede que uma mensagem assinada seja,
    # por acidente ou por golpe, um sighash de transacao valido.
    preimg = MSG_MAGIC + varint(len(payload)) + payload
    z = int.from_bytes(hash256(preimg), "big")
    return ecdsa_sign(priv, z), z

texto = "Eu controlo esta carteira. nonce=7a3f9c  sessao=liveness-42"
(rm, sm), zm = sign_message(PRIV, texto)

print()
print("=" * 74)
print("PASSO 6  -  Assinando uma MENSAGEM (nao e' uma transacao!)")
print("=" * 74)
print(f'mensagem : "{texto}"')
print(f"prefixo  : {MSG_MAGIC!r}")
print(f"z        : {zm:064x}")
print(f"r        : {rm:064x}")
print(f"s        : {sm:064x}")
print(f"verificacao: {'VALIDA' if ecdsa_verify(point_mul(PRIV), zm, rm, sm) else 'INVALIDA'}")
print()
print("Repare: nenhum input, nenhum output, nenhuma taxa, nada vai para a rede.")
print("E' apenas uma prova de que quem assinou controla a chave privada.")
print("O prefixo magico garante que este 'z' NUNCA podera' ser o sighash de uma")
print("transacao real -- ou seja, ninguem pode te enganar a assinar uma mensagem")
print("que, na verdade, gastaria os seus bitcoins.")
print("=" * 74)
