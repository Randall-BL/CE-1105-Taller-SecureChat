#!/usr/bin/env python3
"""
Pruebas automáticas de los requisitos de seguridad de SecureChat.

  python3 -m unittest -v test_securechat.py
"""

import socket
import tempfile
import threading
import unittest
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization

import securechat as sc


def _pares(tmp):
    a = sc.cargar_o_generar_claves("alice", Path(tmp))
    b = sc.cargar_o_generar_claves("bob", Path(tmp))
    return a, b


_SOCKETS = []


class Espia:
    """Registra todos los bytes que pasan por el socket (como un sniffer)."""

    def __init__(self):
        self.bytes = bytearray()

    def __call__(self, direccion, datos):
        self.bytes += datos


def _sesion_completa(tmp, espia=None, pin_a=None):
    (priv_a, pub_a, *_), (priv_b, pub_b, *_) = _pares(tmp)
    sa, sb = socket.socketpair()
    _SOCKETS.extend((sa, sb))
    ca, cb = sc.Canal(sa, espia), sc.Canal(sb)
    res = {}

    def bob():
        res["b"] = sc.handshake_receptor(cb, "Bob", priv_b, pub_b, verbose=False)

    t = threading.Thread(target=bob)
    t.start()
    res["a"] = sc.handshake_iniciador(ca, "Alice", priv_a, pub_a, pin_a, verbose=False)
    t.join()
    return ca, cb, res["a"][0], res["b"][0], (priv_a, priv_b)


def _der_privada(priv):
    return priv.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                              serialization.NoEncryption())


class TestSecureChat(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = self._tmp.name

    def tearDown(self):
        while _SOCKETS:
            _SOCKETS.pop().close()
        self._tmp.cleanup()

    def test_claves_rsa_2048_y_privada_con_permisos_600(self):
        priv, pub, f_priv, f_pub, nueva = sc.cargar_o_generar_claves("alice", Path(self.tmp))
        self.assertTrue(nueva)
        self.assertGreaterEqual(priv.key_size, 2048)
        self.assertEqual(f_priv.stat().st_mode & 0o777, 0o600)
        self.assertNotIn(b"PRIVATE", f_pub.read_bytes())

    def test_handshake_ambos_extremos_misma_clave(self):
        ca, cb, sa, sb, _ = _sesion_completa(self.tmp)
        n, ct = sa.cifrar(sc.T_DATA, b"Hola Bob")
        self.assertEqual(sb.descifrar(sc.T_DATA, n + ct), b"Hola Bob")
        n, ct = sb.cifrar(sc.T_DATA, b"Hola Alice")
        self.assertEqual(sa.descifrar(sc.T_DATA, n + ct), b"Hola Alice")

    def test_clave_de_sesion_distinta_en_cada_sesion(self):
        _, _, s1, _, _ = _sesion_completa(self.tmp)
        _, _, s2, _, _ = _sesion_completa(self.tmp)
        n, ct = s1.cifrar(sc.T_DATA, b"x")
        with self.assertRaises(InvalidTag):
            s2._aead.decrypt(n, ct, s2._aad(sc.T_DATA))

    def test_ni_plaintext_ni_clave_privada_ni_clave_sesion_en_el_socket(self):
        espia = Espia()
        generadas = []
        original = sc.os.urandom

        def urandom_registrado(n):
            b = original(n)
            generadas.append(b)
            return b

        sc.os.urandom = urandom_registrado
        try:
            ca, cb, sa, sb, (priv_a, priv_b) = _sesion_completa(self.tmp, espia)
        finally:
            sc.os.urandom = original
        clave_sesion = [b for b in generadas if len(b) == sc.SESSION_KEY_BYTES][0]
        mensajes = ["Hola Bob, mensaje secreto 1", "Segundo mensaje secreto", "Tercero 123"]
        for m in mensajes:
            n, ct = sa.cifrar(sc.T_DATA, m.encode())
            ca.enviar(sc.T_DATA, n + ct)
            _, payload, _ = cb.recibir()
            self.assertEqual(sb.descifrar(sc.T_DATA, payload).decode(), m)
        capturado = bytes(espia.bytes)
        for m in mensajes:
            self.assertNotIn(m.encode(), capturado)
        for priv in (priv_a, priv_b):
            der = _der_privada(priv)
            self.assertNotIn(der, capturado)
            self.assertNotIn(der[-64:], capturado)       # ni un fragmento
        self.assertNotIn(b"PRIVATE KEY", capturado)
        self.assertNotIn(clave_sesion, capturado)            # K solo viaja cifrada con RSA

    def test_nonce_nunca_se_repite(self):
        _, _, sa, sb, _ = _sesion_completa(self.tmp)
        nonces = set()
        for s in (sa, sb):
            for _ in range(1000):
                n, _ = s.cifrar(sc.T_DATA, b"m")
                self.assertNotIn(n, nonces)
                nonces.add(n)
        self.assertEqual(len(nonces), 2000)

    def test_mismo_texto_produce_ciphertext_distinto(self):
        _, _, sa, _, _ = _sesion_completa(self.tmp)
        _, c1 = sa.cifrar(sc.T_DATA, b"repetido")
        _, c2 = sa.cifrar(sc.T_DATA, b"repetido")
        self.assertNotEqual(c1, c2)   # no es ECB / no es determinista

    def test_ciphertext_alterado_es_rechazado(self):
        _, _, sa, sb, _ = _sesion_completa(self.tmp)
        n, ct = sa.cifrar(sc.T_DATA, b"transferir 100")
        trama = bytearray(n + ct)
        for i in range(len(trama)):          # cualquier byte: nonce, ct o tag
            alterada = bytearray(trama)
            alterada[i] ^= 0x01
            with self.assertRaises(InvalidTag, msg=f"byte {i}"):
                sb.descifrar(sc.T_DATA, bytes(alterada))
        # tras rechazar la alterada, la legítima sigue aceptándose
        self.assertEqual(sb.descifrar(sc.T_DATA, bytes(trama)), b"transferir 100")

    def test_replay_rechazado(self):
        _, _, sa, sb, _ = _sesion_completa(self.tmp)
        n, ct = sa.cifrar(sc.T_DATA, b"una vez")
        sb.descifrar(sc.T_DATA, n + ct)
        with self.assertRaises(sc.ErrorProtocolo):
            sb.descifrar(sc.T_DATA, n + ct)

    def test_pin_de_clave_publica_detecta_suplantacion(self):
        impostor = sc.cargar_o_generar_claves("mallory", Path(self.tmp))[3]
        with self.assertRaises(sc.ErrorProtocolo):
            _sesion_completa_pin_falla(self.tmp, impostor)


def _sesion_completa_pin_falla(tmp, pin):
    (priv_a, pub_a, *_), (priv_b, pub_b, *_) = _pares(tmp)
    sa, sb = socket.socketpair()

    def bob():
        try:
            sc.handshake_receptor(sc.Canal(sb), "Bob", priv_b, pub_b, verbose=False)
        except Exception:
            pass

    t = threading.Thread(target=bob, daemon=True)
    t.start()
    try:
        sc.handshake_iniciador(sc.Canal(sa), "Alice", priv_a, pub_a, pin, verbose=False)
    finally:
        sa.close()
        sb.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
