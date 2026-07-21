#!/usr/bin/env python3
# =============================================================================
#  binding_protocol.py  -  Parte 2 do laboratorio.
#
#  Implementa, EM CODIGO REAL, o protocolo do artigo:
#
#       m = H( nonce || hash(tx) || id_sessao )
#
#  ...e depois ATACA cada garantia, para demonstrar concretamente o modelo
#  de ameacas da Secao 6 do trabalho (replay, expiracao, ancora de confianca).
#
#  ZERO dependencias. Mesma cripto (secp256k1/ECDSA) da Parte 1.
#  Nada toca a rede: tudo sao bytes e assinaturas construidos na sua maquina.
# =============================================================================

import hashlib, hmac

# -----------------------------------------------------------------------------
# 0. CRIPTO  (identica a Parte 1 - copiada para o script rodar sozinho)
# -----------------------------------------------------------------------------
def sha256(b):  return hashlib.sha256(b).digest()
def hash256(b): return sha256(sha256(b))

P  = 2**256 - 2**32 - 977
N  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G  = (Gx, Gy)

def point_add(a, b):
    if a is None: return b
    if b is None: return a
    if a[0] == b[0] and (a[1] + b[1]) % P == 0: return None
    if a == b: lam = (3*a[0]*a[0]) * pow(2*a[1], P-2, P) % P
    else:      lam = (b[1]-a[1]) * pow(b[0]-a[0], P-2, P) % P
    x = (lam*lam - a[0] - b[0]) % P
    y = (lam*(a[0]-x) - a[1]) % P
    return (x, y)

def point_mul(k, pt=G):
    r = None
    while k:
        if k & 1: r = point_add(r, pt)
        pt = point_add(pt, pt); k >>= 1
    return r

def pubkey_compressed(priv):
    x, y = point_mul(priv)
    return (b"\x02" if y % 2 == 0 else b"\x03") + x.to_bytes(32, "big")

def _rfc6979_k(priv, z):
    v = b"\x01"*32; k = b"\x00"*32
    zb, pb = z.to_bytes(32,"big"), priv.to_bytes(32,"big")
    k = hmac.new(k, v+b"\x00"+pb+zb, hashlib.sha256).digest(); v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v+b"\x01"+pb+zb, hashlib.sha256).digest(); v = hmac.new(k, v, hashlib.sha256).digest()
    while True:
        v = hmac.new(k, v, hashlib.sha256).digest()
        c = int.from_bytes(v, "big")
        if 1 <= c < N: return c
        k = hmac.new(k, v+b"\x00", hashlib.sha256).digest(); v = hmac.new(k, v, hashlib.sha256).digest()

def ecdsa_sign(priv, z):
    k = _rfc6979_k(priv, z)
    r = point_mul(k)[0] % N
    s = (pow(k, N-2, N) * (z + r*priv)) % N
    if s > N//2: s = N - s
    return (r, s)

def ecdsa_verify(pub_point, z, sig):
    r, s = sig
    if not (1 <= r < N and 1 <= s < N): return False
    w  = pow(s, N-2, N)
    p1 = point_mul((z*w) % N)
    p2 = point_mul((r*w) % N, pub_point)
    pt = point_add(p1, p2)
    return pt is not None and pt[0] % N == r

# helpers de alto nivel: assinar/verificar sobre BYTES (fazemos o hash256 dentro)
def sign_bytes(priv, msg):        return ecdsa_sign(priv, int.from_bytes(hash256(msg), "big"))
def verify_bytes(pub_pt, msg, s): return ecdsa_verify(pub_pt, int.from_bytes(hash256(msg), "big"), s)

def line(t=""): print(("== " + t + " ").ljust(76, "=") if t else "="*76)

# -----------------------------------------------------------------------------
# 1. OS ATORES E SUAS CHAVES
# -----------------------------------------------------------------------------
# Usuario (mesma chave da Parte 1) - controla a carteira autocustodiada.
USER_PRIV = 0xC0FFEE00000000000000000000000000000000000000000000000000DECAFBAD
USER_PUB  = pubkey_compressed(USER_PRIV)
USER_PT   = point_mul(USER_PRIV)

# Provedor de atestacao (liveness) - tem a PROPRIA chave, que co-assina.
PROV_PRIV = 0x00000000000000000000000000000000000000000000000000000000ABCDEF01
PROV_PUB  = pubkey_compressed(PROV_PRIV)
PROV_PT   = point_mul(PROV_PRIV)

# O VASP so confia em provedores desta lista (as "chaves de atestacao credenciadas").
PROVEDORES_CONFIAVEIS = { PROV_PUB }

# A transacao a autorizar: reaproveitamos a tx CRUA da Parte 1 (bytes reais).
UNSIGNED_TX_HEX = (
 "0200000001a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3b2c156308a7e4b1d2c9f"
 "0000000000ffffffff02801d2c04000000001976a9141369b55aaf58093fc0f25e2d27eee"
 "1ba04512f3388ac709cc901000000001976a914316d5d0910e3b3ac16b1226d45ab16d6c5"
 "a50f7e88ac00000000")
TX_HASH = hash256(bytes.fromhex(UNSIGNED_TX_HEX))   # o hash(tx) do artigo

# Parametros da sessao (fixos aqui para a saida ser reproduzivel; na vida real
# nonce e' aleatorio e T e' o relogio no instante do liveness).
NONCE      = bytes.fromhex("7a3f9c1e5d2b8046")      # frescor
SESSION_ID = b"liveness-2026-42"                    # id da sessao de liveness
T          = 1_760_000_000                          # instante do liveness (epoch)
JANELA     = 300                                    # 5 min de validade

line("PROTOCOLO DE BINDING  -  os atores")
print(f"Usuario  (carteira) pub : {USER_PUB.hex()}")
print(f"Provedor (liveness) pub : {PROV_PUB.hex()}")
print(f"hash(tx) a autorizar    : {TX_HASH.hex()}")
print(f"nonce={NONCE.hex()}  sessao={SESSION_ID.decode()}  T={T}  janela={JANELA}s")

# -----------------------------------------------------------------------------
# 2. AS DUAS FUNCOES CENTRAIS: montar 'm' e a atestacao
# -----------------------------------------------------------------------------
def montar_m(nonce, tx_hash, session_id):
    """m = H( nonce || hash(tx) || id_sessao )  -- o que o USUARIO assina."""
    return hash256(nonce + tx_hash + session_id)

def montar_atestacao(session_id, user_pub, tx_hash, t, veredito=b"liveness=pass"):
    """Bytes canonicos que o PROVEDOR co-assina (analogo a um payload EIP-712)."""
    return (b"ATTEST\x00" + session_id + b"|" + user_pub + b"|"
            + tx_hash + b"|" + t.to_bytes(8, "big") + b"|" + veredito)

# -----------------------------------------------------------------------------
# 3. O FLUXO HONESTO
# -----------------------------------------------------------------------------
line("PASSO A  -  Usuario assina o compromisso (o 'Sign Confirmation')")
m = montar_m(NONCE, TX_HASH, SESSION_ID)
sig_user = sign_bytes(USER_PRIV, m)
print(f"m = H(nonce || hash(tx) || sessao) = {m.hex()}")
print(f"sig_user r = {sig_user[0]:064x}")
print(f"sig_user s = {sig_user[1]:064x}")
print("-> prova que quem assinou CONTROLA A CHAVE. (ainda nao prova a pessoa)")

line("PASSO B  -  Provedor faz o liveness (off-chain) e co-assina a atestacao")
attest = montar_atestacao(SESSION_ID, USER_PUB, TX_HASH, T)
sig_prov = sign_bytes(PROV_PRIV, attest)
print("liveness verificado off-chain ...... [OK, simulado]")
print(f"atestacao (campos): sessao={SESSION_ID.decode()} | carteira={USER_PUB.hex()[:12]}...")
print(f"                    tx={TX_HASH.hex()[:12]}... | T={T} | veredito=liveness=pass")
print(f"atestacao (bytes) : {attest.hex()}")
print(f"sig_prov r = {sig_prov[0]:064x}")
print("-> acrescenta a afirmacao 'um humano vivo passou no liveness nesta sessao'")

# --- O verificador (o VASP) ---
def verificar(bundle, agora):
    """Retorna (aprovado: bool, motivos: list[str]). Espelha a Figura 1 do artigo."""
    motivos = []
    # 1) assinatura do usuario sobre m -> controle da chave
    m_ = montar_m(bundle["nonce"], bundle["tx_hash"], bundle["session_id"])
    if verify_bytes(bundle["user_pt"], m_, bundle["sig_user"]):
        motivos.append("[ok] sig_user valida sobre m  -> controle da chave")
    else:
        motivos.append("[X ] sig_user NAO bate com m  -> controle da chave FALHOU")
        return False, motivos
    # 2) provedor e' credenciado?
    if bundle["prov_pub"] in PROVEDORES_CONFIAVEIS:
        motivos.append("[ok] provedor esta na lista de confiaveis")
    else:
        motivos.append("[X ] provedor NAO credenciado")
        return False, motivos
    # 3) assinatura do provedor sobre a atestacao -> liveness
    a_ = montar_atestacao(bundle["session_id"], bundle["user_pub"],
                          bundle["tx_hash"], bundle["att_T"], bundle["att_veredito"])
    if verify_bytes(bundle["prov_pt"], a_, bundle["sig_prov"]):
        motivos.append("[ok] sig_prov valida sobre a atestacao -> liveness atestado")
    else:
        motivos.append("[X ] sig_prov invalida -> liveness NAO atestado")
        return False, motivos
    # 4) BINDING: a atestacao fala da MESMA sessao, MESMA tx, MESMA carteira?
    if (bundle["att_session"] == bundle["session_id"]
            and bundle["att_tx"] == bundle["tx_hash"]
            and bundle["att_user"] == bundle["user_pub"]):
        motivos.append("[ok] binding: sessao/tx/carteira batem entre m e atestacao")
    else:
        motivos.append("[X ] binding QUEBRADO: atestacao fala de outra sessao/tx")
        return False, motivos
    # 5) frescor
    dt = agora - bundle["att_T"]
    if 0 <= dt <= JANELA:
        motivos.append(f"[ok] frescor: {dt}s dentro da janela de {JANELA}s")
    else:
        motivos.append(f"[X ] EXPIRADO: {dt}s fora da janela de {JANELA}s")
        return False, motivos
    return True, motivos

def bundle_honesto():
    return {
        "nonce": NONCE, "tx_hash": TX_HASH, "session_id": SESSION_ID,
        "user_pub": USER_PUB, "user_pt": USER_PT, "sig_user": sig_user,
        "prov_pub": PROV_PUB, "prov_pt": PROV_PT, "sig_prov": sig_prov,
        "att_session": SESSION_ID, "att_tx": TX_HASH, "att_user": USER_PUB,
        "att_T": T, "att_veredito": b"liveness=pass",
    }

def julgar(titulo, bundle, agora):
    ok, motivos = verificar(bundle, agora)
    print()
    line(titulo)
    for mtv in motivos: print("   " + mtv)
    print(f"   => {'APROVADO' if ok else 'REJEITADO'}")
    return ok

julgar("PASSO C  -  Verificacao do fluxo honesto", bundle_honesto(), agora=T + 30)

# =============================================================================
#  A PARTIR DAQUI: OS ATAQUES  (a Secao 6 do artigo, executavel)
# =============================================================================
print("\n\n" + "#"*76 + "\n#  ANALISE CRITICA EXECUTAVEL  -  quebrando cada garantia\n" + "#"*76)

# -----------------------------------------------------------------------------
# ATAQUE 1 - REPLAY para OUTRA transacao
# -----------------------------------------------------------------------------
# O atacante intercepta a sig_user (o Sign Confirmation) do usuario e tenta
# usa-la para autorizar uma transacao DIFERENTE (outro destinatario).
TX2_HEX  = UNSIGNED_TX_HEX.replace("1369b55aaf58093fc0f25e2d27eee1ba04512f33",
                                   "dead00beef00dead00beef00dead00beef00dead")  # outro destino
TX2_HASH = hash256(bytes.fromhex(TX2_HEX))

b = bundle_honesto()
b["tx_hash"] = TX2_HASH        # atacante troca a tx...
# ...mas reaproveita a MESMA sig_user (nao tem a chave do usuario p/ reassinar)
ok1 = julgar("ATAQUE 1 - reusar o Sign Confirmation em outra tx", b, agora=T + 30)

print("\n   Por que falhou: m depende de hash(tx). Trocar a tx muda m, e a")
print("   assinatura do usuario deixa de bater. O hash(tx) dentro de m e' o")
print("   que AMARRA a prova aquela transacao especifica.")
print()
print("   Contraste (a abordagem ingenua, tipo AOPP): se o usuario tivesse")
print("   assinado apenas 'eu sou dono da carteira X', SEM hash(tx)...")
msg_estatica = b"Eu sou dono da carteira " + USER_PUB
sig_estatica = sign_bytes(USER_PRIV, msg_estatica)
vale_para_tx1 = verify_bytes(USER_PT, msg_estatica, sig_estatica)
vale_para_tx2 = verify_bytes(USER_PT, msg_estatica, sig_estatica)  # mesma msg: nao depende da tx!
print(f"     a mesma assinatura estatica vale para a tx1? {vale_para_tx1}")
print(f"     e vale tambem para a tx2 (do atacante)?      {vale_para_tx2}  <- EIS O PROBLEMA")
print("   Sem binding a transacao, a prova de titularidade e' reutilizavel.")

# -----------------------------------------------------------------------------
# ATAQUE 2 - REPLAY de um bundle VALIDO, porem fora da janela (TOCTOU/expiracao)
# -----------------------------------------------------------------------------
ok2 = julgar("ATAQUE 2 - reapresentar um bundle valido, mas velho",
             bundle_honesto(), agora=T + JANELA + 60)
print("\n   Por que falhou: o par (nonce, T) da frescor. Passada a janela, o")
print("   mesmo bundle expira. Isso limita o intervalo entre o liveness e o")
print("   uso (o TOCTOU) -- mas note: encolhe a brecha, nao a elimina.")

# -----------------------------------------------------------------------------
# ATAQUE 3 - O MURO: a ancora de confianca off-chain
# -----------------------------------------------------------------------------
# Nenhum liveness real aconteceu. Um provedor DESONESTO (mas credenciado)
# simplesmente co-assina 'liveness=pass'. O usuario (ou quem detem a chave)
# assina m normalmente. O verificador aprova -- sem que humano algum tenha
# sido verificado.
attest_falsa = montar_atestacao(SESSION_ID, USER_PUB, TX_HASH, T)  # provedor NAO checou nada
sig_prov_falsa = sign_bytes(PROV_PRIV, attest_falsa)              # ...mas assina mesmo assim

b = bundle_honesto()
b["sig_prov"] = sig_prov_falsa
ok3 = julgar("ATAQUE 3 - provedor credenciado co-assina SEM liveness real", b, agora=T + 30)
print("\n   Por que PASSOU: criptografia nenhuma consegue provar que a camera")
print("   viu um humano vivo. O verificador so' checa a ASSINATURA do provedor,")
print("   nao o que ele de fato fez. A seguranca do protocolo nunca e' maior")
print("   que a confianca no atestador -- a 'ancora off-chain inescapavel' da")
print("   Secao 6.2. Deepfake e coacao vivem AQUI, ANTES da assinatura, fora")
print("   do alcance de qualquer verificacao on-chain.")

# -----------------------------------------------------------------------------
# FECHAMENTO
# -----------------------------------------------------------------------------
print()
line("RESUMO EXECUTAVEL DA SECAO 6")
print(f"   Fluxo honesto .......................... APROVADO   ({'ok' if True else ''})")
print(f"   Ataque 1 (replay outra tx) ............. {'REJEITADO' if not ok1 else 'PASSOU?!'}   <- binding via hash(tx)")
print(f"   Ataque 2 (bundle expirado) ............. {'REJEITADO' if not ok2 else 'PASSOU?!'}   <- frescor via nonce+T")
print(f"   Ataque 3 (provedor desonesto) .......... {'APROVADO' if ok3 else 'REJEITADO'}   <- LIMITE INTRANSPONIVEL")
print()
print("   Conclusao que sustenta o trabalho: o protocolo ELEVA O CUSTO da")
print("   fraude e amarra a prova a uma tx (vs. AOPP), mas NAO entrega")
print("   confiabilidade de 100% -- porque reduz a confianca a um atestador")
print("   off-chain. Rota viavel, com um teto honesto.")
line()
