# Cómo ejecutar SecureChat y sus pruebas en otra PC

Guía para que cualquier persona pueda probar el proyecto desde cero, en **Windows, Linux o macOS**.
Tiempo estimado: 5–10 minutos.

> **Convención de comandos**
> - **Linux / macOS:** usar `python3`
> - **Windows:** usar `py` (o `python` si `py` no existe)
>
> En esta guía, cada vez que aparezca `python3`, en Windows se escribe `py`.

---

## 1. Requisitos

| Requisito | Cómo verificarlo | Si falta |
|---|---|---|
| **Python 3.8 o superior** | `python3 --version` (Windows: `py --version`) | Descargar de <https://www.python.org/downloads/>. En Windows, marcar **"Add python.exe to PATH"** durante la instalación. |
| **pip** | `python3 -m pip --version` | Linux (Debian/Ubuntu): `sudo apt install python3-pip python3-venv` |
| **Conexión a Internet** | Solo una vez, para instalar la librería `cryptography`. | — |

No se necesita nada más: el programa usa sockets TCP sobre `127.0.0.1`, así que todo corre en
la misma computadora y no hay que abrir puertos en el firewall.

---

## 2. Obtener el proyecto

**Opción A — desde el archivo comprimido:**
descomprimir `SecureChat_Taller2.zip` (clic derecho → *Extraer todo…*) y abrir una terminal
dentro de la carpeta `SecureChat_Taller2`.

**Opción B — desde GitHub:**

```bash
git clone https://github.com/Randall-BL/CE-1105-Taller-SecureChat.git
cd CE-1105-Taller-SecureChat
```

> **¿Cómo abrir una terminal en la carpeta?**
> - **Windows:** abrir la carpeta en el Explorador, escribir `cmd` en la barra de direcciones
>   y pulsar Enter. También sirve clic derecho → *Abrir en Terminal*.
> - **Linux:** clic derecho → *Abrir en una terminal*.
> - **macOS:** clic derecho sobre la carpeta → *Servicios* → *Nueva terminal en la carpeta*.

---

## 3. Instalar dependencias (una sola vez)

Se recomienda un entorno virtual para no tocar el Python del sistema.

**Linux / macOS**
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

**Windows (CMD)**
```bat
py -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

**Windows (PowerShell)**
```powershell
py -m venv venv
venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

> Si PowerShell bloquea el script de activación, primero ejecutar:
> `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`

Con el entorno activado aparece `(venv)` al inicio de la línea, y dentro de él `python`
funciona en todos los sistemas. **Cada terminal nueva** que se abra (pasos 5 y 6) debe
activar el entorno otra vez, con la línea `activate` de arriba.

---

## 4. Ejecutar las pruebas automáticas

```bash
python -m unittest -v test_securechat.py
```

**Resultado esperado:** 9 pruebas y al final `OK`.

```
test_ciphertext_alterado_es_rechazado ... ok
test_clave_de_sesion_distinta_en_cada_sesion ... ok
test_claves_rsa_2048_y_privada_con_permisos_600 ... ok
test_handshake_ambos_extremos_misma_clave ... ok
test_mismo_texto_produce_ciphertext_distinto ... ok
test_ni_plaintext_ni_clave_privada_ni_clave_sesion_en_el_socket ... ok
test_nonce_nunca_se_repite ... ok
test_pin_de_clave_publica_detecta_suplantacion ... ok
test_replay_rechazado ... ok
----------------------------------------------------------------------
Ran 9 tests in 1.0s

OK
```

| Prueba | Qué comprueba |
|---|---|
| `claves_rsa_2048_y_privada_con_permisos_600` | Las claves RSA son de ≥ 2048 bits y la privada queda protegida en disco. En Windows se omite la parte de permisos. |
| `handshake_ambos_extremos_misma_clave` | Tras el handshake, Alice y Bob pueden cifrar y descifrar entre sí. |
| `clave_de_sesion_distinta_en_cada_sesion` | La clave de sesión se genera de nuevo en cada conexión; no está fija en el código. |
| `ni_plaintext_ni_clave_privada_ni_clave_sesion_en_el_socket` | Un "sniffer" captura todos los bytes del socket. Ni los mensajes, ni las claves privadas, ni la clave de sesión aparecen en claro. |
| `nonce_nunca_se_repite` | 2000 cifrados (1000 por lado) sin ningún nonce repetido. |
| `mismo_texto_produce_ciphertext_distinto` | Cifrar dos veces el mismo texto da resultados distintos, es decir, no es ECB. |
| `ciphertext_alterado_es_rechazado` | Alterar **cualquier** byte (nonce, ciphertext o tag) hace que el mensaje se rechace. |
| `replay_rechazado` | Reenviar un mensaje ya recibido se detecta y se rechaza. |
| `pin_de_clave_publica_detecta_suplantacion` | Si llega una clave pública distinta de la esperada, se aborta la conexión. |

---

## 5. Prueba manual: chat en dos terminales

Abrir **dos terminales** en la carpeta del proyecto y activar el entorno virtual en ambas.

**Terminal 1 — Bob (abrirla primero):**
```bash
python securechat.py escuchar --nombre Bob
```

**Terminal 2 — Alice:**
```bash
python securechat.py conectar --nombre Alice
```

Ambas deben mostrar el handshake y el mensaje `✓ SESIÓN SEGURA ESTABLECIDA`. A partir de ahí,
escribir mensajes en cualquiera de las dos y pulsar Enter.

| Comando dentro del chat | Efecto |
|---|---|
| `Hola Bob` (cualquier texto) | Se envía cifrado con AES-256-GCM. |
| `/alterar Hola` | Cifra el mensaje y **cambia un byte** antes de enviarlo. El otro lado debe mostrar `✗ MENSAJE RECHAZADO`. |
| `/ayuda` | Muestra la ayuda. |
| `/salir` | Cierra la sesión de forma ordenada. |

Qué debe verse en cada mensaje:

- **Quien envía:** el texto original, y debajo el nonce, el ciphertext, el tag y los bytes
  exactos enviados por el socket.
- **Quien recibe:** los mismos bytes, la línea `✓ tag GCM verificado` y, solo entonces, el
  mensaje legible.

---

## 6. Prueba completa: con un "atacante" en medio (tres terminales)

`mitm_proxy.py` se coloca entre Alice y Bob. Muestra lo que vería un espía en la red y
altera un mensaje para demostrar que se detecta.

**Terminal 1 — Bob:**
```bash
python securechat.py escuchar --nombre Bob --puerto 5000
```

**Terminal 2 — Proxy atacante (altera la 7.ª trama de datos):**
```bash
python mitm_proxy.py --escuchar 6000 --destino 5000 --alterar 7 --captura captura.bin
```

**Terminal 3 — Alice (se conecta al proxy, no directamente a Bob):**
```bash
python securechat.py conectar --nombre Alice --puerto 6000
```

**Conversación sugerida.** El orden importa para que la alteración caiga en el mensaje 7.

| # | Quién escribe | Mensaje | Resultado esperado |
|---|---|---|---|
| 1 | Alice | `Hola Bob` | Bob lo lee ✓ |
| 2 | Bob | `Hola Alice, te leo cifrado` | Alice lo lee ✓ |
| 3 | Alice | `El codigo secreto es 4321` | Bob lo lee ✓ |
| 4 | Bob | `Recibido, nadie mas lo ve` | Alice lo lee ✓ |
| 5 | Alice | `Tercer mensaje de Alice` | Bob lo lee ✓ |
| 6 | Bob | `Tercer mensaje de Bob` | Alice lo lee ✓ |
| 7 | Alice | `Transferir 100 colones a Bob` | **El proxy lo altera → Bob: `✗ MENSAJE RECHAZADO`** |
| 8 | Bob | `/alterar mensaje alterado por Bob` | **Alice: `✗ MENSAJE RECHAZADO`** |
| 9 | Alice | `Este si llega bien` | Bob lo lee ✓: la sesión sigue funcionando |
| 10 | Alice | `/salir` | Ambos cierran la sesión; el proxy guarda `captura.bin`. |

En Bob, tras el `/salir` de Alice, pulsar Enter para terminar.

### Verificar que nada viajó en claro

Este comando funciona igual en Windows, Linux y macOS. Busca los textos en los bytes que
capturó el proxy:

```bash
python -c "d=open('captura.bin','rb').read(); [print(repr(t), '->', d.count(t)) for t in (b'Hola Bob', b'4321', b'Transferir', b'PRIVATE')]"
```

**Resultado esperado:** todo en `0`.

```
b'Hola Bob' -> 0
b'4321' -> 0
b'Transferir' -> 0
b'PRIVATE' -> 0
```

En Linux y macOS también se puede hacer con `grep -a -c "Hola Bob" captura.bin`.

---

## 7. Problemas frecuentes

| Problema | Solución |
|---|---|
| `python3` / `py` no se reconoce | Python no está instalado o no está en el PATH. Reinstalarlo marcando *Add to PATH*, o probar con `python`. |
| `ensurepip is not available` o `python3 -m venv` falla (Ubuntu/Debian) | Instalar el módulo de entornos virtuales: `sudo apt install python3-venv`, borrar la carpeta `venv` y repetir el paso 3. **Sin sudo:** omitir el entorno virtual e instalar solo para el usuario con `python3 -m pip install --user cryptography`. Si pip responde *externally-managed-environment*, agregar `--break-system-packages`. Después usar `python3` en lugar de `python`. |
| `ModuleNotFoundError: No module named 'cryptography'` | No se activó el entorno virtual en esa terminal, o falta `pip install -r requirements.txt`. |
| `OSError: [Errno 98] Address already in use` / `WinError 10048` | El puerto está ocupado, por ejemplo por una ejecución anterior. Esperar unos segundos o usar otro: `--puerto 5050` en Bob **y** en Alice. |
| `ConnectionRefusedError` en Alice | Bob (o el proxy) no está escuchando todavía. Arrancarlo primero. |
| Aparecen caracteres raros como `←[36m` en Windows | La consola antigua no entiende colores. Usar *Windows Terminal*, o desactivar los colores con `set NO_COLOR=1` (CMD) o `$env:NO_COLOR=1` (PowerShell) antes de ejecutar. |
| El firewall de Windows pregunta si permitir Python | Se puede aceptar o cancelar: el tráfico es solo local (`127.0.0.1`) y funciona igual. |
| Volver a empezar con claves nuevas | Borrar la carpeta `claves/`. Se regeneran solas al ejecutar. |

---

## 8. Archivos del proyecto

| Archivo | Descripción |
|---|---|
| `securechat.py` | Programa principal (chat cifrado). |
| `mitm_proxy.py` | Proxy "atacante" para la demostración. |
| `test_securechat.py` | Pruebas automáticas. |
| `requirements.txt` | Dependencias (`cryptography`). |
| `README.md` | Documentación del protocolo y respuestas a las preguntas del taller. |
| `Informe_SecureChat.pdf` | Informe con capturas de una ejecución real. |
| `evidencia/` | Salidas de referencia de una ejecución completa, para comparar. |
