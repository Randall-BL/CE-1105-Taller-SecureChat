#!/usr/bin/env python3
"""
Proxy "atacante en la red" para la demostración de SecureChat.

Se coloca entre Alice y Bob, reenvía las tramas y muestra exactamente qué ve
un tercero que captura el tráfico. Opcionalmente altera 1 byte del ciphertext
de una trama DATA para demostrar que AES-GCM detecta la manipulación.

  Terminal 1 (Bob):    python3 securechat.py escuchar --nombre Bob --puerto 5000
  Terminal 2 (proxy):  python3 mitm_proxy.py --escuchar 6000 --destino 5000 --alterar 2
  Terminal 3 (Alice):  python3 securechat.py conectar --nombre Alice --puerto 6000

  --alterar N   altera la N-ésima trama DATA (contando ambas direcciones).
  --captura F   guarda los bytes crudos capturados en F (para buscar el plaintext
                con grep y comprobar que no aparece).
"""

import argparse
import socket
import struct
import sys
import threading

from securechat import NOMBRES_TIPO, NONCE_BYTES, T_DATA, hex_corto, rojo, amarillo, gris, negrita

_lock = threading.Lock()
_contador_data = 0


def _leer(sock, n):
    buf = bytearray()
    while len(buf) < n:
        b = sock.recv(n - len(buf))
        if not b:
            raise ConnectionError
        buf += b
    return bytes(buf)


def reenviar(origen, destino, etiqueta, args, archivo):
    global _contador_data
    try:
        while True:
            cab = _leer(origen, 4)
            (largo,) = struct.unpack(">I", cab)
            cuerpo = bytearray(_leer(origen, largo))
            tipo = cuerpo[0]
            alterada = False
            with _lock:
                if tipo == T_DATA:
                    _contador_data += 1
                    if args.alterar and _contador_data == args.alterar:
                        i = 1 + NONCE_BYTES          # 1er byte del ciphertext
                        cuerpo[i] ^= 0x01
                        alterada = True
                trama = cab + bytes(cuerpo)
                if archivo:
                    archivo.write(trama)
                    archivo.flush()
                print(negrita(f"[{etiqueta}] {NOMBRES_TIPO.get(tipo, hex(tipo))}") +
                      f"  {len(trama)} B")
                if tipo == 0x01:  # HELLO: es público, se muestra tal cual
                    print(gris("    " + cuerpo[1:121].decode(errors="replace").replace("\n", "\\n") + " …"))
                else:
                    print(gris("    " + hex_corto(trama, 80)))
                if alterada:
                    print(rojo(f"    ⚠ PROXY ALTERÓ el byte {4 + 1 + NONCE_BYTES} de la trama "
                               f"(1er byte del ciphertext, XOR 0x01)"))
                sys.stdout.flush()
            destino.sendall(trama)
    except (ConnectionError, OSError):
        pass
    finally:
        for s in (origen, destino):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--escuchar", type=int, default=6000, help="puerto donde se conecta Alice")
    ap.add_argument("--destino", type=int, default=5000, help="puerto donde escucha Bob")
    ap.add_argument("--alterar", type=int, default=0, metavar="N",
                    help="altera la N-ésima trama DATA (0 = no alterar)")
    ap.add_argument("--captura", metavar="ARCHIVO", help="guarda los bytes crudos capturados")
    args = ap.parse_args()

    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", args.escuchar))
    srv.listen(1)
    print(amarillo(f"Proxy escuchando en 127.0.0.1:{args.escuchar} → reenvía a 127.0.0.1:{args.destino}"))
    if args.alterar:
        print(rojo(f"Modo ataque: se alterará la trama DATA número {args.alterar}"))
    cli, _ = srv.accept()
    srv.close()
    srv_dest = socket.create_connection(("127.0.0.1", args.destino))
    archivo = open(args.captura, "wb") if args.captura else None

    hilos = [threading.Thread(target=reenviar, args=(cli, srv_dest, "Alice→Bob", args, archivo)),
             threading.Thread(target=reenviar, args=(srv_dest, cli, "Bob→Alice", args, archivo))]
    for h in hilos:
        h.start()
    for h in hilos:
        h.join()
    if archivo:
        archivo.close()
        print(amarillo(f"Captura guardada en {args.captura}"))
    print(amarillo("Proxy finalizado."))


if __name__ == "__main__":
    main()
