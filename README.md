# SecureChat: chat cifrado con criptografía híbrida

**Curso:** CE-1105 Seguridad de la Información, Taller de Criptografía Aplicada
**Estudiante(s):** Randall Bolaños (carné ________) · Javier Tenorio (carné ________)
**Fecha:** ____ de octubre de 2026

Es un chat de consola entre dos procesos en la misma computadora. Se comunican por un socket
TCP sobre `127.0.0.1`.

- **Handshake (asimétrico):** RSA-2048. Usa OAEP-SHA256 para proteger la clave de sesión y
  PSS-SHA256 para firmarla.
- **Conversación (simétrica autenticada):** AES-256-GCM, con nonce de 96 bits que nunca se
  repite y tag de 128 bits.

---

## 1. Contenido del proyecto

| Archivo | Para qué sirve |
|---|---|
| `securechat.py` | La aplicación. Un único programa que se ejecuta dos veces: `escuchar` (Bob) y `conectar` (Alice). |
| `mitm_proxy.py` | Proxy "atacante en la red". Se pone entre Alice y Bob, muestra los bytes que realmente viajan y puede **alterar un byte** del ciphertext. |
| `test_securechat.py` | 9 pruebas automáticas de los requisitos de seguridad. |
| `requirements.txt` | Dependencia: `cryptography`. |
| `capturas/` | Capturas de una ejecución real (se usan en el informe). |
| `evidencia/` | Salida completa de esa ejecución: `alice.log`, `bob.log`, `proxy.log`, `tests.log` y `captura.bin` (los bytes crudos que capturó el proxy). |
| `Informe_SecureChat.pdf` / `.tex` | Documentación en formato informe: protocolo, evidencias y preguntas de cierre. |
| `GUION_VIDEO.md` | Guion paso a paso para grabar el video de 4–6 min. |

## 2. Instalación

Requiere Python ≥ 3.8.

```bash
python3 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## 3. Ejecución básica (dos terminales)

```bash
# Terminal B (primero): Bob espera conexiones en 127.0.0.1:5000
python3 securechat.py escuchar --nombre Bob

# Terminal A: Alice se conecta
python3 securechat.py conectar --nombre Alice
```

La primera vez, cada participante genera su par RSA-2048 en `claves/<nombre>_privada.pem`
(permisos 600) y `claves/<nombre>_publica.pem`. Las siguientes veces lo reutiliza. La clave
privada **nunca** se imprime ni se envía. En pantalla solo aparece la ruta y la huella de la
clave pública.

Cuando termina el handshake, ambas terminales muestran **`✓ SESIÓN SEGURA ESTABLECIDA con <par>`**,
junto con los nombres y los puertos de cada extremo. Desde ese momento se puede escribir.

| Comando | Efecto |
|---|---|
| `<texto>` | Envía el mensaje cifrado con AES-256-GCM. |
| `/alterar <texto>` | **Prueba de manipulación:** cifra el mensaje y cambia 1 byte del ciphertext antes de enviarlo. |
| `/ayuda` | Muestra la ayuda. |
| `/salir` (o Ctrl+D / Ctrl+C) | Cierre controlado: envía un `BYE` cifrado y cierra el socket. |

Cada mensaje muestra cuatro tipos de evidencia, distinguidos por color:

- **Emisor (cian):** el plaintext local y luego el nonce, el ciphertext, el tag y los bytes
  exactos escritos en el socket.
- **Receptor (magenta):** los bytes recibidos del socket, con su nonce y su ciphertext+tag.
- **Receptor (verde):** `✓ tag GCM verificado` y, **solo entonces**, el plaintext recuperado.
- **Receptor (rojo):** `✗ MENSAJE RECHAZADO` si el tag no verifica. En ese caso no se muestra
  ningún plaintext.

## 4. Reproducir la demostración completa (con atacante en la red)

Se usan tres terminales. El proxy hace de "red": Alice se conecta al proxy y el proxy reenvía
a Bob.

```bash
# Terminal B: Bob
python3 securechat.py escuchar --nombre Bob --puerto 5000

# Terminal C: proxy que muestra el tráfico y ALTERA la 7.ª trama DATA
python3 mitm_proxy.py --escuchar 6000 --destino 5000 --alterar 7 --captura captura.bin

# Terminal A: Alice (se conecta al proxy, no directamente a Bob)
python3 securechat.py conectar --nombre Alice --puerto 6000
```

Conversación sugerida, con 3 mensajes por lado y luego la prueba de alteración:

1. Alice: `Hola Bob` → Bob: `Hola Alice, te leo cifrado`
2. Alice: `El codigo secreto es 4321` → Bob: `Recibido, nadie mas lo ve`
3. Alice: `Tercer mensaje de Alice` → Bob: `Tercer mensaje de Bob`
4. Alice: `Transferir 100 colones a Bob`. Es la 7.ª trama DATA, así que **el proxy la
   altera** y Bob la rechaza.
5. Bob: `/alterar mensaje alterado por Bob`. El emisor altera el mensaje y Alice lo rechaza.
6. Alice: `Este si llega bien`. Bob lo acepta, lo que muestra que la sesión sigue sana.
7. Alice: `/salir`.

Después se comprueba que ningún mensaje viajó en claro:

```bash
grep -a -c "Hola Bob"   captura.bin     # → 0
grep -a -c "4321"       captura.bin     # → 0
grep -a -c "PRIVATE"    captura.bin     # → 0 (ninguna clave privada cruzó el socket)
```

También se puede ver el tráfico real con Wireshark o tcpdump en la interfaz `lo`
(`sudo tcpdump -i lo -X port 5000`).

## 5. Pruebas automáticas

```bash
python3 -m unittest -v test_securechat.py
```

Las pruebas verifican lo siguiente:

- RSA ≥ 2048 bits y clave privada con permisos 600.
- Ambos extremos obtienen la misma clave.
- La clave de sesión es distinta en cada sesión, es decir, no está hardcodeada.
- **Ni el plaintext, ni la clave privada, ni la clave de sesión aparecen en los bytes del
  socket.**
- Ningún nonce se repite en 2000 cifrados.
- El mismo texto produce ciphertexts distintos (no es ECB).
- Alterar **cualquier** byte (nonce, ciphertext o tag) produce un rechazo.
- Se detecta el replay.
- El *pinning* de la clave pública detecta a un impostor.

---

## 6. Protocolo implementado

### 6.1 Algoritmos y tamaños

| Elemento | Algoritmo | Tamaño |
|---|---|---|
| Par asimétrico de cada participante | RSA, e = 65537 | 2048 bits |
| Protección de la clave de sesión | RSA-OAEP, MGF1-SHA256, hash SHA-256 | 256 B cifrados |
| Autenticación del que envía la clave | Firma RSA-PSS-SHA256 (clave privada de Alice) | 256 B |
| Clave de sesión | `os.urandom(32)` (CSPRNG), nueva en cada ejecución | 256 bits |
| Cifrado de mensajes | AES-256-GCM (AEAD) | nonce 96 bits, tag 128 bits |
| Datos asociados (AAD) | `"SecureChat-v1" ‖ tipo de trama ‖ H` | — |
| Resumen del handshake | H = SHA-256(`"SecureChat-v1"` ‖ HELLO_A ‖ HELLO_B) | 32 B |

### 6.2 Handshake

```
 Alice (conectar)                                         Bob (escuchar)
 ── TCP connect 127.0.0.1:5000 ─────────────────────────────►
 HELLO {nombre:"Alice", pubA (PEM)}  ───────────────────────►   (público)
                          ◄──────────────────────────────── HELLO {nombre:"Bob", pubB (PEM)}
 K  = os.urandom(32)                       ← clave AES-256 de sesión
 C  = RSA-OAEP(pubB, K)                    ← solo privB puede abrirla
 S  = RSA-PSS-Sign(privA, H ‖ C)           ← prueba que viene de Alice
 KEY_EXCHANGE  C ‖ S  ──────────────────────────────────────►  Verify(pubA, S)
                                                                K = RSA-OAEP⁻¹(privB, C)
                          ◄──────────────────────────────── SESSION_OK = AES-GCM_K("SESSION-OK")
 descifra y verifica SESSION_OK
 ═════════ ambos tienen K → "✓ SESIÓN SEGURA ESTABLECIDA" → chat AES-256-GCM ═════════
```

- La clave de sesión **K** solo cruza el socket cifrada con la clave pública de Bob. No está
  escrita en el código.
- Las claves **privadas** nunca salen del disco local.
- `SESSION_OK` es la "confirmación de sesión". Como va cifrada y autenticada con K, Alice
  comprueba que Bob realmente obtuvo la misma K.
- Opcional: `--clave-par claves/bob_publica.pem` fija la clave pública esperada del otro
  extremo (*pinning*). Si llega otra, se aborta. Esto protege frente a un intermediario que
  sustituya las claves públicas en el HELLO. Si no se usa, se pueden comparar a ojo las
  huellas que imprimen ambas terminales.

### 6.3 Estructura de las tramas en el socket

Todas las tramas tienen esta forma:

```
┌──────────────┬────────┬──────────────────────────────┐
│ longitud (4B)│ tipo 1B│ payload                      │
└──────────────┴────────┴──────────────────────────────┘
```

| Tipo | Nombre | Payload | ¿Cifrado? |
|---|---|---|---|
| `0x01` | HELLO | JSON `{nombre, clave_publica}` | No (es información pública) |
| `0x02` | KEY_EXCHANGE | `RSA-OAEP(K)` (256 B) ‖ firma PSS (256 B) | K va cifrada con RSA |
| `0x03` | SESSION_OK | nonce ‖ ciphertext ‖ tag | AES-256-GCM |
| `0x10` | DATA | nonce (12 B) ‖ ciphertext (n B) ‖ tag (16 B) | AES-256-GCM |
| `0x11` | BYE | nonce ‖ ciphertext ‖ tag | AES-256-GCM |

**Nonce** (12 B) = prefijo de dirección (4 B: `00000001` Alice→Bob, `00000002` Bob→Alice) ‖
contador de 64 bits.

- El contador solo aumenta, así que un extremo nunca repite su nonce.
- El prefijo distinto por dirección impide que los nonces de Alice y Bob coincidan, aunque
  compartan K.
- El receptor exige que el contador sea estrictamente creciente, lo que da protección
  anti-replay.

Ejemplo real de la trama de `"Hola Bob"` (41 bytes, sacado de `evidencia/alice.log`):

```
0000 0025 | 10 | 0000 0001 0000 0000 0000 0000 | 89e8 19b0 2b49 bb5a | f42e c623 7b1f 7be7 c272 013e 490a 77a8
 longitud  tipo        nonce (dir=1, ctr=0)         ciphertext (8 B)            tag GCM (16 B)
```

El texto "Hola Bob" (`486f 6c61 2042 6f62`) no aparece en ningún punto de la trama.

---

## 7. Preguntas de cierre

**1. ¿Qué problema resuelve la criptografía asimétrica durante el handshake?**
Resuelve la distribución de claves. Alice y Bob no comparten ningún secreto previo, y el
canal TCP es observable. Con RSA-OAEP, Alice cifra la clave de sesión con la clave
**pública** de Bob, que cualquiera puede conocer. Solo la clave **privada** de Bob, que nunca
sale de su equipo, puede descifrarla. Así ambos acuerdan un secreto simétrico sin enviarlo
nunca en claro. Además, la firma RSA-PSS de Alice autentica quién generó esa clave.

**2. ¿Por qué la conversación utiliza criptografía simétrica después del handshake?**
Por eficiencia y por diseño:

- AES-GCM es órdenes de magnitud más rápido que RSA.
- AES-GCM cifra datos de cualquier tamaño. RSA-OAEP-2048 solo puede cifrar unos 190 bytes
  por operación y produce 256 bytes de salida.
- AES-GCM incluye autenticación (integridad).

La parte costosa (RSA) se usa una sola vez para acordar K. Todos los mensajes se protegen
después con la primitiva rápida.

**3. ¿Qué información puede observar un tercero que capture los paquetes?**

- IPs y puertos, y el momento y el tamaño de cada trama. GCM no oculta la longitud, así que
  se puede inferir el largo aproximado de cada mensaje.
- Los HELLO: nombres de los participantes y sus claves **públicas**.
- La clave de sesión cifrada con RSA y la firma.
- Por cada mensaje: tipo de trama, nonce (con el contador visible), ciphertext y tag.

**No** puede ver el contenido de los mensajes, la clave de sesión ni las claves privadas.
`evidencia/proxy.log` y `captura.bin` muestran exactamente lo que ve.

**4. ¿Por qué el nonce puede viajar junto al ciphertext y por qué no debe repetirse?**
El nonce **no es secreto**: su función es hacer único cada cifrado, y la seguridad depende
solo de la clave. El receptor lo necesita para descifrar, así que se envía en claro.

En cambio, **nunca debe repetirse con la misma clave**. GCM cifra en modo contador (CTR):
dos mensajes con el mismo nonce usan el mismo keystream. Haciendo `C1 ⊕ C2` se obtiene
`P1 ⊕ P2`, lo que filtra el contenido. Además, la repetición permite recuperar la clave de
autenticación GHASH y **falsificar tags**. Por eso el programa usa un contador
monotónico con prefijo por dirección.

**5. ¿Qué función cumple el authentication tag?**
Es un código de autenticación de mensaje de 128 bits. Se calcula con la clave de sesión
sobre el ciphertext y los datos asociados, que incluyen la versión, el tipo de trama y el
resumen del handshake. El receptor lo recalcula **antes** de entregar el plaintext. Si
cambió un solo bit del nonce, del ciphertext, del tag o del contexto, la verificación falla
(`InvalidTag`) y el mensaje se rechaza sin mostrar texto.

El tag garantiza integridad y autenticidad: el mensaje viene de alguien que tiene K y no fue
modificado. Esto es lo que demuestra la prueba de alteración. Cifrar sin autenticar (por
ejemplo, AES-CTR solo) permitiría alterar bits del plaintext sin que nadie lo detectara.

**6. ¿Qué ocurriría si la clave de sesión se transmitiera sin protección?**
Cualquiera que capturara el tráfico, por ejemplo con el proxy o con Wireshark, obtendría K.
Con K podría:

- **descifrar todos los mensajes** de la sesión;
- **fabricar o modificar mensajes** con tags válidos, porque el tag también depende de K, y
  el receptor los aceptaría como auténticos.

AES-GCM no aportaría ninguna seguridad. Codificarla en Base64 o hex tampoco ayudaría:
codificar no es cifrar.

**7. ¿Qué ocurriría si un atacante obtiene una de las claves privadas?**

- **Con la privada de Bob:** puede descifrar el `KEY_EXCHANGE` de cualquier sesión que haya
  capturado, ya sea **pasada o futura**, obtener K y leer toda esa conversación. Este diseño
  (transporte de clave con RSA) **no tiene *forward secrecy***. Además, puede hacerse pasar
  por Bob ante Alice.
- **Con la privada de Alice:** puede firmar `KEY_EXCHANGE` falsos y suplantar a Alice ante
  Bob. No puede descifrar sesiones pasadas, porque K va cifrada para Bob.

**Mitigaciones:**

- proteger las privadas (permisos 600, cifrado con contraseña o HSM);
- revocarlas y regenerarlas si se filtran;
- usar un intercambio efímero (ECDHE/X25519) firmado con las claves RSA para obtener
  *forward secrecy*, como hace TLS 1.3.

## 8. Limitaciones conocidas

- La autenticidad de las claves públicas depende de verificar la huella o de usar
  `--clave-par`. No hay PKI ni certificados.
- No hay *forward secrecy* (ver la pregunta 7).
- La longitud de los mensajes es visible.
- Las claves privadas se guardan sin contraseña para simplificar la demo; están protegidas
  solo con permisos 600.
