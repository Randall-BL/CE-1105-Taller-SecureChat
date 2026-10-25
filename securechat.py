#!/usr/bin/env python3
"""
SecureChat: chat cifrado entre dos procesos locales (criptografía híbrida).

  - Handshake:    RSA-2048 (OAEP-SHA256 para proteger la clave de sesión,
                  PSS-SHA256 para que el iniciador firme lo que envía).
  - Conversación: AES-256-GCM (cifrado autenticado), nonce de 96 bits
                  = prefijo de dirección (4 B) + contador (8 B), nunca repetido.

Uso rápido (dos terminales):
  Terminal B:  python3 securechat.py escuchar --nombre Bob
  Terminal A:  python3 securechat.py conectar --nombre Alice

Comandos dentro del chat: /ayuda  /alterar <texto>  /salir
"""

import argparse
import hashlib
import json
import os
import socket
import struct
import sys
import threading
from pathlib import Path

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ───────────────────────── Parámetros del protocolo ─────────────────────────

VERSION = b"SecureChat-v1"
RSA_BITS = 2048
SESSION_KEY_BYTES = 32          # AES-256
NONCE_BYTES = 12                # 96 bits, recomendado para GCM
TAG_BYTES = 16                  # 128 bits (lo añade AESGCM al final del ct)
MAX_FRAME = 1 << 20             # 1 MiB, evita que un par malicioso agote memoria

# Tipos de trama
T_HELLO = 0x01        # {nombre, clave pública}           — público, sin cifrar
T_KEY_EXCHANGE = 0x02 # RSA-OAEP(K) || firma PSS          — K nunca va en claro
T_SESSION_OK = 0x03   # AES-GCM("SESSION-OK")             — prueba de posesión de K
T_DATA = 0x10         # nonce || ciphertext || tag        — mensaje de chat
T_BYE = 0x11          # nonce || ciphertext || tag        — cierre controlado

NOMBRES_TIPO = {T_HELLO: "HELLO", T_KEY_EXCHANGE: "KEY_EXCHANGE",
                T_SESSION_OK: "SESSION_OK", T_DATA: "DATA", T_BYE: "BYE"}

# Prefijos de nonce: cada dirección usa uno distinto, así Alice y Bob jamás
# generan el mismo nonce aunque compartan la misma clave de sesión.
PREFIJO_INICIADOR = b"\x00\x00\x00\x01"
PREFIJO_RECEPTOR = b"\x00\x00\x00\x02"

OAEP = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                    algorithm=hashes.SHA256(), label=None)
PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                  salt_length=padding.PSS.MAX_LENGTH)


class ErrorProtocolo(Exception):
    pass


# ───────────────────────────── Presentación ─────────────────────────────────

_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
if _COLOR and os.name == "nt":
    os.system("")  # activa las secuencias ANSI en la consola clásica de Windows
_print_lock = threading.Lock()


def _c(codigo, texto):
    return f"\033[{codigo}m{texto}\033[0m" if _COLOR else texto


def verde(t): return _c("1;32", t)
def rojo(t): return _c("1;31", t)
def amarillo(t): return _c("33", t)
def cian(t): return _c("36", t)
def magenta(t): return _c("35", t)
def gris(t): return _c("2", t)
def negrita(t): return _c("1", t)


def log(*lineas):
    with _print_lock:
        for linea in lineas:
            print(linea)
        sys.stdout.flush()


def hex_corto(b: bytes, maximo=64):
    """Hex en grupos de 2 bytes; trunca si es muy largo (solo para mostrar)."""
    h = b[:maximo].hex()
    h = " ".join(h[i:i + 4] for i in range(0, len(h), 4))
    return h + (f" … (+{len(b) - maximo} B)" if len(b) > maximo else "")


def huella(pub) -> str:
    """Huella SHA-256 de la clave pública (DER/SPKI), para verificarla a ojo."""
    der = pub.public_bytes(serialization.Encoding.DER,
                           serialization.PublicFormat.SubjectPublicKeyInfo)
    h = hashlib.sha256(der).hexdigest()[:32]
    return ":".join(h[i:i + 4] for i in range(0, len(h), 4))


# ─────────────────────────── Material asimétrico ────────────────────────────

def cargar_o_generar_claves(nombre: str, carpeta: Path):
    """Carga el par RSA del participante o lo genera la primera vez.

    La clave privada se guarda solo en disco local (permisos 600) y nunca se
    imprime ni se envía. La pública se guarda aparte y es la única que viaja.
    """
    carpeta.mkdir(parents=True, exist_ok=True)
    base = nombre.lower()
    f_priv = carpeta / f"{base}_privada.pem"
    f_pub = carpeta / f"{base}_publica.pem"

    if f_priv.exists():
        priv = serialization.load_pem_private_key(f_priv.read_bytes(), password=None)
        nueva = False
    else:
        priv = rsa.generate_private_key(public_exponent=65537, key_size=RSA_BITS)
        f_priv.write_bytes(priv.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
        os.chmod(f_priv, 0o600)
        nueva = True

    pub = priv.public_key()
    f_pub.write_bytes(pub.public_bytes(serialization.Encoding.PEM,
                                       serialization.PublicFormat.SubjectPublicKeyInfo))
    if priv.key_size < RSA_BITS:
        raise ErrorProtocolo(f"La clave RSA de {nombre} tiene {priv.key_size} bits (< {RSA_BITS})")
    return priv, pub, f_priv, f_pub, nueva


def pem_publica(pub) -> str:
    return pub.public_bytes(serialization.Encoding.PEM,
                            serialization.PublicFormat.SubjectPublicKeyInfo).decode()


# ──────────────────────────── Transporte (TCP) ──────────────────────────────

class Canal:
    """Tramas sobre TCP:  [longitud: 4 B big-endian][tipo: 1 B][payload]

    `espia` (opcional) recibe ("tx"|"rx", bytes_crudos) de todo lo que pasa por
    el socket; lo usan las pruebas para comprobar que no viaja plaintext.
    """

    def __init__(self, sock: socket.socket, espia=None):
        self.sock = sock
        self.espia = espia
        self._lock_tx = threading.Lock()

    def enviar(self, tipo: int, payload: bytes) -> bytes:
        trama = struct.pack(">IB", len(payload) + 1, tipo) + payload
        with self._lock_tx:
            self.sock.sendall(trama)
        if self.espia:
            self.espia("tx", trama)
        return trama

    def _leer_exacto(self, n: int) -> bytes:
        buf = bytearray()
        while len(buf) < n:
            trozo = self.sock.recv(n - len(buf))
            if not trozo:
                raise ConnectionError("el otro extremo cerró la conexión")
            buf += trozo
        return bytes(buf)

    def recibir(self):
        cab = self._leer_exacto(4)
        (largo,) = struct.unpack(">I", cab)
        if not 1 <= largo <= MAX_FRAME:
            raise ErrorProtocolo(f"longitud de trama inválida: {largo}")
        cuerpo = self._leer_exacto(largo)
        if self.espia:
            self.espia("rx", cab + cuerpo)
        return cuerpo[0], cuerpo[1:], cab + cuerpo

    def recibir_tipo(self, esperado: int) -> bytes:
        tipo, payload, _ = self.recibir()
        if tipo != esperado:
            raise ErrorProtocolo(f"se esperaba {NOMBRES_TIPO.get(esperado)} y llegó "
                                 f"{NOMBRES_TIPO.get(tipo, hex(tipo))}")
        return payload


# ─────────────────────── Sesión simétrica (AES-GCM) ─────────────────────────

class SesionSegura:
    """Cifra/descifra con AES-256-GCM usando la clave de sesión negociada.

    Nonce (12 B) = prefijo de dirección (4 B) || contador (8 B big-endian).
      * El contador de envío solo crece → nunca se repite un nonce propio.
      * Los prefijos distintos por dirección → los nonces de Alice y Bob
        nunca colisionan aunque usen la misma clave.
      * El receptor exige contador estrictamente creciente → anti-replay.
    """

    def __init__(self, clave: bytes, prefijo_propio: bytes, prefijo_par: bytes, contexto: bytes):
        if len(clave) != SESSION_KEY_BYTES:
            raise ValueError("la clave de sesión debe tener 32 bytes")
        self._aead = AESGCM(clave)
        self._prefijo_propio = prefijo_propio
        self._prefijo_par = prefijo_par
        self._contexto = contexto          # hash del handshake, va como AAD
        self._ctr_tx = 0
        self._ultimo_rx = -1
        self.nonces_usados = set()         # solo para demostrar/verificar unicidad

    def _aad(self, tipo: int) -> bytes:
        # Datos asociados: autenticados pero no cifrados. Atan cada mensaje a
        # esta sesión concreta y a su tipo de trama (DATA no se puede hacer
        # pasar por BYE, ni un mensaje de otra sesión por uno de esta).
        return VERSION + bytes([tipo]) + self._contexto

    def cifrar(self, tipo: int, texto: bytes):
        if self._ctr_tx >= 2 ** 64:
            raise ErrorProtocolo("contador de nonce agotado; renegocie la sesión")
        nonce = self._prefijo_propio + self._ctr_tx.to_bytes(8, "big")
        self._ctr_tx += 1
        assert nonce not in self.nonces_usados
        self.nonces_usados.add(nonce)
        ct_y_tag = self._aead.encrypt(nonce, texto, self._aad(tipo))
        return nonce, ct_y_tag

    def descifrar(self, tipo: int, payload: bytes) -> bytes:
        """Devuelve el plaintext SOLO si el tag es válido; si no, lanza InvalidTag."""
        if len(payload) < NONCE_BYTES + TAG_BYTES:
            raise InvalidTag()
        nonce, ct_y_tag = payload[:NONCE_BYTES], payload[NONCE_BYTES:]
        # decrypt() verifica el tag ANTES de devolver nada: si un solo bit del
        # nonce, ciphertext, tag o AAD cambió, lanza InvalidTag y no hay texto.
        texto = self._aead.decrypt(nonce, ct_y_tag, self._aad(tipo))
        if nonce[:4] != self._prefijo_par:
            raise ErrorProtocolo("nonce con prefijo de dirección incorrecto")
        ctr = int.from_bytes(nonce[4:], "big")
        if ctr <= self._ultimo_rx:
            raise ErrorProtocolo(f"mensaje repetido (replay): contador {ctr}")
        self._ultimo_rx = ctr
        return texto


def empaquetar(nonce: bytes, ct_y_tag: bytes) -> bytes:
    return nonce + ct_y_tag


# ──────────────────────────────── Handshake ─────────────────────────────────
#
#   Alice (conectar)                                   Bob (escuchar)
#   HELLO {nombre, pubA}  ───────────────────────────►
#                         ◄─────────────────────────── HELLO {nombre, pubB}
#   K = os.urandom(32)
#   C = RSA-OAEP(pubB, K)
#   S = RSA-PSS(privA, H || C)
#   KEY_EXCHANGE C || S   ───────────────────────────►  verifica S con pubA
#                                                       K = RSA-OAEP⁻¹(privB, C)
#                         ◄─────────────────────────── SESSION_OK = AES-GCM_K("SESSION-OK")
#   verifica SESSION_OK
#   ═══════════ ambos tienen K → chat con AES-256-GCM ═══════════
#
#   H = SHA-256(VERSION || HELLO_A || HELLO_B)  (resumen del transcript)

def _hello(nombre: str, pub) -> bytes:
    return json.dumps({"nombre": nombre, "clave_publica": pem_publica(pub)},
                      ensure_ascii=False).encode()


def _leer_hello(payload: bytes):
    datos = json.loads(payload.decode())
    pub = serialization.load_pem_public_key(datos["clave_publica"].encode())
    if not isinstance(pub, rsa.RSAPublicKey) or pub.key_size < RSA_BITS:
        raise ErrorProtocolo("la clave pública del par no es RSA ≥ 2048 bits")
    return datos["nombre"], pub


def _transcript(hello_ini: bytes, hello_rec: bytes) -> bytes:
    return hashlib.sha256(VERSION + hello_ini + hello_rec).digest()


def _comprobar_pin(pub_par, pin_path):
    if pin_path is None:
        return
    esperado = serialization.load_pem_public_key(Path(pin_path).read_bytes())
    if huella(esperado) != huella(pub_par):
        raise ErrorProtocolo("la clave pública recibida NO coincide con la esperada "
                             "(posible ataque de intermediario)")


def handshake_iniciador(canal: Canal, nombre, priv, pub, pin_par=None, verbose=True):
    """Lado que conecta (Alice). Genera la clave de sesión y la protege con RSA."""
    say = log if verbose else (lambda *a: None)

    hello_a = _hello(nombre, pub)
    canal.enviar(T_HELLO, hello_a)
    say(gris(f"  [1/4] → HELLO enviado ({nombre} + clave pública, {len(hello_a)} B)"))

    hello_b = canal.recibir_tipo(T_HELLO)
    nombre_par, pub_par = _leer_hello(hello_b)
    _comprobar_pin(pub_par, pin_par)
    say(gris(f"  [2/4] ← HELLO de {nombre_par}; huella de su clave pública: {huella(pub_par)}"))

    h = _transcript(hello_a, hello_b)
    clave = os.urandom(SESSION_KEY_BYTES)          # generada en tiempo de ejecución
    c = pub_par.encrypt(clave, OAEP)                # solo privB puede abrirla
    firma = priv.sign(h + c, PSS, hashes.SHA256())  # prueba que lo envía Alice
    canal.enviar(T_KEY_EXCHANGE, c + firma)
    say(gris(f"  [3/4] → KEY_EXCHANGE: clave AES-256 generada y cifrada con RSA-OAEP "
             f"({len(c)} B) + firma RSA-PSS ({len(firma)} B)"),
        gris(f"        clave de sesión cifrada (lo que viaja): {hex_corto(c, 24)}"))

    sesion = SesionSegura(clave, PREFIJO_INICIADOR, PREFIJO_RECEPTOR, h)
    ok = canal.recibir_tipo(T_SESSION_OK)
    try:
        if sesion.descifrar(T_SESSION_OK, ok) != b"SESSION-OK":
            raise ErrorProtocolo("confirmación de sesión inválida")
    except InvalidTag:
        raise ErrorProtocolo("la confirmación de sesión no verifica: el par no tiene la clave")
    say(gris(f"  [4/4] ← SESSION_OK verificado con AES-GCM: {nombre_par} posee la misma clave"))
    return sesion, nombre_par, pub_par


def handshake_receptor(canal: Canal, nombre, priv, pub, pin_par=None, verbose=True):
    """Lado que escucha (Bob). Recupera la clave de sesión con su clave privada."""
    say = log if verbose else (lambda *a: None)

    hello_a = canal.recibir_tipo(T_HELLO)
    nombre_par, pub_par = _leer_hello(hello_a)
    _comprobar_pin(pub_par, pin_par)
    say(gris(f"  [1/4] ← HELLO de {nombre_par}; huella de su clave pública: {huella(pub_par)}"))

    hello_b = _hello(nombre, pub)
    canal.enviar(T_HELLO, hello_b)
    say(gris(f"  [2/4] → HELLO enviado ({nombre} + clave pública, {len(hello_b)} B)"))

    h = _transcript(hello_a, hello_b)
    datos = canal.recibir_tipo(T_KEY_EXCHANGE)
    largo = priv.key_size // 8
    c, firma = datos[:largo], datos[largo:]
    try:
        pub_par.verify(firma, h + c, PSS, hashes.SHA256())
    except InvalidSignature:
        raise ErrorProtocolo(f"firma del KEY_EXCHANGE inválida: no proviene de {nombre_par}")
    clave = priv.decrypt(c, OAEP)
    say(gris(f"  [3/4] ← KEY_EXCHANGE: firma de {nombre_par} válida; clave de sesión "
             f"recuperada con mi clave privada (RSA-OAEP)"))

    sesion = SesionSegura(clave, PREFIJO_RECEPTOR, PREFIJO_INICIADOR, h)
    nonce, ct = sesion.cifrar(T_SESSION_OK, b"SESSION-OK")
    canal.enviar(T_SESSION_OK, empaquetar(nonce, ct))
    say(gris("  [4/4] → SESSION_OK enviado (cifrado con la clave de sesión)"))
    return sesion, nombre_par, pub_par


# ─────────────────────────────── Chat (UI) ──────────────────────────────────

AYUDA = f"""{negrita('Comandos:')}
  <texto>            envía el mensaje cifrado con AES-256-GCM
  /alterar <texto>   PRUEBA DE MANIPULACIÓN: cifra el mensaje y modifica 1 byte
                     del ciphertext antes de enviarlo (simula un atacante en la red)
  /ayuda             muestra esta ayuda
  /salir             cierra la sesión de forma controlada"""


class Chat:
    def __init__(self, canal: Canal, sesion: SesionSegura, yo: str, par: str):
        self.canal, self.sesion, self.yo, self.par = canal, sesion, yo, par
        self.activo = threading.Event()
        self.activo.set()

    # --- envío ---
    def enviar(self, texto: str, alterar=False):
        plano = texto.encode("utf-8")
        nonce, ct = self.sesion.cifrar(T_DATA, plano)
        payload = bytearray(empaquetar(nonce, ct))
        lineas = [
            cian(f"┌─ [YO → {self.par}]  plaintext local: ") + negrita(repr(texto)),
            cian("│  nonce (12 B):".ljust(24)) + hex_corto(nonce),
            cian(f"│  ciphertext ({len(ct) - TAG_BYTES} B):".ljust(24)) + hex_corto(ct[:-TAG_BYTES]),
            cian("│  tag GCM (16 B):".ljust(24)) + hex_corto(ct[-TAG_BYTES:]),
        ]
        if alterar:
            i = NONCE_BYTES  # primer byte del ciphertext
            antes = payload[i]
            payload[i] ^= 0x01
            lineas.append(rojo(f"│  ⚠ ALTERADO: byte {i} del payload 0x{antes:02x} → 0x{payload[i]:02x} "
                               f"(simulación de atacante)"))
        trama = self.canal.enviar(T_DATA, bytes(payload))
        lineas.append(cian(f"└─ bytes en el socket ({len(trama)} B): ") + gris(hex_corto(trama, 96)))
        log(*lineas)

    # --- recepción (hilo) ---
    def bucle_recepcion(self):
        try:
            while self.activo.is_set():
                tipo, payload, trama = self.canal.recibir()
                if tipo == T_DATA:
                    self._recibir_dato(payload, trama)
                elif tipo == T_BYE:
                    try:
                        self.sesion.descifrar(T_BYE, payload)
                        log(amarillo(f"\n*** {self.par} cerró la sesión. Pulse Enter para salir. ***"))
                    except (InvalidTag, ErrorProtocolo):
                        log(rojo("*** BYE con autenticación inválida: ignorado ***"))
                        continue
                    break
                else:
                    log(rojo(f"*** trama inesperada tipo {tipo:#x}: descartada ***"))
        except (ConnectionError, OSError) as e:
            if self.activo.is_set():
                log(amarillo(f"\n*** Conexión cerrada ({e}). Pulse Enter para salir. ***"))
        except ErrorProtocolo as e:
            log(rojo(f"\n*** Error de protocolo: {e} ***"))
        finally:
            self.activo.clear()

    def _recibir_dato(self, payload: bytes, trama: bytes):
        nonce, ct = payload[:NONCE_BYTES], payload[NONCE_BYTES:]
        cab = [
            magenta(f"┌─ [{self.par} → YO]  bytes recibidos del socket ({len(trama)} B): ")
            + gris(hex_corto(trama, 96)),
            magenta("│  nonce: ") + hex_corto(nonce)
            + magenta(f"   ciphertext+tag ({len(ct)} B): ") + hex_corto(ct, 48),
        ]
        try:
            texto = self.sesion.descifrar(T_DATA, payload).decode("utf-8")
        except InvalidTag:
            log(*cab,
                rojo("│  ✗ AUTENTICACIÓN FALLIDA: el tag GCM no coincide."),
                rojo("└─ ✗ MENSAJE RECHAZADO — fue alterado en tránsito; no se muestra ningún plaintext."))
            return
        except ErrorProtocolo as e:
            log(*cab, rojo(f"└─ ✗ MENSAJE RECHAZADO — {e}"))
            return
        log(*cab,
            verde("│  ✓ tag GCM verificado: integridad y autenticidad OK"),
            verde(f"└─ {self.par} dice: ") + negrita(texto))

    # --- cierre ---
    def cerrar(self, avisar=True):
        if avisar and self.activo.is_set():
            try:
                nonce, ct = self.sesion.cifrar(T_BYE, b"BYE")
                self.canal.enviar(T_BYE, empaquetar(nonce, ct))
            except OSError:
                pass
        self.activo.clear()
        try:
            self.canal.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.canal.sock.close()

    def ejecutar(self):
        hilo = threading.Thread(target=self.bucle_recepcion, daemon=True)
        hilo.start()
        log(AYUDA, "")
        try:
            while self.activo.is_set():
                try:
                    linea = input()
                except EOFError:
                    break
                if not self.activo.is_set():
                    break
                linea = linea.strip()
                if not linea:
                    continue
                if linea == "/salir":
                    break
                if linea == "/ayuda":
                    log(AYUDA)
                elif linea.startswith("/alterar"):
                    texto = linea[len("/alterar"):].strip() or "mensaje que será alterado"
                    self.enviar(texto, alterar=True)
                elif linea.startswith("/"):
                    log(amarillo("Comando desconocido. Escriba /ayuda."))
                else:
                    self.enviar(linea)
        except KeyboardInterrupt:
            pass
        finally:
            self.cerrar()
            log(amarillo("Sesión finalizada. Clave de sesión descartada."))


# ─────────────────────────────── Programa ───────────────────────────────────

def _ruta(p: Path) -> str:
    try:
        return str(p.resolve().relative_to(Path.cwd()))
    except ValueError:
        return str(p)


def banner(nombre, modo, f_priv, f_pub, pub, nueva):
    log(negrita("═" * 72),
        negrita(f"  SecureChat — {nombre}  ({modo})"),
        negrita("═" * 72),
        f"  Par RSA-{RSA_BITS} {'GENERADO' if nueva else 'cargado'}:",
        f"    clave pública : {_ruta(f_pub)}   (se comparte en el handshake)",
        f"    huella pública: {huella(pub)}",
        f"    clave privada : {_ruta(f_priv)}   " + amarillo("(local, permisos 600, NUNCA se muestra ni se envía)"),
        "")


def main(argv=None):
    ap = argparse.ArgumentParser(description="SecureChat: chat cifrado RSA-OAEP + AES-256-GCM")
    ap.add_argument("modo", choices=["escuchar", "conectar"],
                    help="escuchar = espera la conexión (Bob); conectar = inicia la conexión (Alice)")
    ap.add_argument("--nombre", required=True, help="nombre del participante, p. ej. Alice o Bob")
    ap.add_argument("--host", default="127.0.0.1", help="dirección (por defecto 127.0.0.1)")
    ap.add_argument("--puerto", type=int, default=5000, help="puerto TCP (por defecto 5000)")
    ap.add_argument("--claves", default=str(Path(__file__).with_name("claves")),
                    help="carpeta donde se guardan los pares RSA")
    ap.add_argument("--clave-par", metavar="PEM",
                    help="(opcional) clave pública esperada del otro participante; si no coincide, "
                         "se aborta el handshake (protección contra intermediario)")
    args = ap.parse_args(argv)

    priv, pub, f_priv, f_pub, nueva = cargar_o_generar_claves(args.nombre, Path(args.claves))
    banner(args.nombre, args.modo, f_priv, f_pub, pub, nueva)

    if args.modo == "escuchar":
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((args.host, args.puerto))
        srv.listen(1)
        log(f"Esperando conexión en {args.host}:{args.puerto} …")
        sock, addr = srv.accept()
        srv.close()
        log(f"Conexión TCP aceptada desde {addr[0]}:{addr[1]}")
    else:
        sock = socket.create_connection((args.host, args.puerto))
        log(f"Conectado por TCP a {args.host}:{args.puerto} "
            f"(puerto local {sock.getsockname()[1]})")

    canal = Canal(sock)
    log(negrita("\nHandshake (criptografía asimétrica):"))
    try:
        if args.modo == "conectar":
            sesion, par, pub_par = handshake_iniciador(canal, args.nombre, priv, pub, args.clave_par)
        else:
            sesion, par, pub_par = handshake_receptor(canal, args.nombre, priv, pub, args.clave_par)
    except (ErrorProtocolo, ConnectionError, ValueError) as e:
        log(rojo(f"\n✗ Handshake fallido: {e}"))
        sock.close()
        return 1

    log("", verde("═" * 72),
        verde(f"  ✓ SESIÓN SEGURA ESTABLECIDA con {par}"),
        verde(f"    {args.nombre} ⇄ {par}  |  {sock.getsockname()[0]}:{sock.getsockname()[1]} ⇄ "
              f"{sock.getpeername()[0]}:{sock.getpeername()[1]}"),
        verde("    Mensajes protegidos con AES-256-GCM (nonce 96 bits, tag 128 bits)"),
        verde("═" * 72), "")

    Chat(canal, sesion, args.nombre, par).ejecutar()
    return 0


if __name__ == "__main__":
    sys.exit(main())
