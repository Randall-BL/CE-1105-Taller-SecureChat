# Guion del video de demostración (4–6 min)

**Preparación (antes de grabar):**
- Abrir 3 terminales en la carpeta del proyecto, lado a lado: **A = Alice** (izquierda),
  **C = proxy** (centro, más angosta) y **B = Bob** (derecha). Se puede usar el modo mosaico
  de GNOME (Super+←/→) o Terminator.
- Subir el tamaño de letra (Ctrl+Shift++) para que el hex sea legible en el video.
- `rm -rf claves/ captura.bin` para empezar desde cero y que se vea la generación de claves.
- Grabador: **Ctrl+Shift+Alt+R** (grabador integrado de GNOME), OBS Studio o
  `simplescreenrecorder`. Activar el micrófono.
- Si son pareja, **ambos deben hablar**. Una idea es que uno narre la Parte 1–3 y el otro la
  Parte 4–6.

---

### Parte 1 · Presentación y arquitectura (≈ 40 s)
> "Este es SecureChat: un chat entre dos procesos en la misma PC por TCP sobre localhost.
> Usa criptografía híbrida: RSA-2048 con OAEP para establecer la sesión y AES-256-GCM para
> cada mensaje. Además tenemos un proxy que hace de atacante en la red: ve todos los bytes y
> puede alterarlos."

Mostrar brevemente la sección 6 del README (diagrama del handshake).

### Parte 2 · Arranque y handshake (≈ 1 min)
1. **Terminal B:** `python3 securechat.py escuchar --nombre Bob --puerto 5000`
2. **Terminal C:** `python3 mitm_proxy.py --escuchar 6000 --destino 5000 --alterar 7 --captura captura.bin`
3. **Terminal A:** `python3 securechat.py conectar --nombre Alice --puerto 6000`

> "Cada uno genera su par RSA-2048. La privada queda en disco con permisos 600 y nunca se
> muestra; solo vemos su ruta y la huella de la pública."
>
> "Handshake: se intercambian las claves **públicas** en el HELLO, que el proxy ve en claro
> porque son públicas. Alice genera una clave AES-256 aleatoria y la cifra con la pública de
> Bob usando RSA-OAEP, y la firma con su privada. El proxy solo ve 256 bytes ilegibles. Bob la
> descifra con su privada y confirma con un SESSION_OK cifrado."

Señalar **✓ SESIÓN SEGURA ESTABLECIDA** en ambas terminales y que las huellas coinciden entre
terminales.

### Parte 3 · Conversación bidireccional (≈ 1 min 30 s)
Escribir los 3 + 3 mensajes, alternando:

| # | Quién | Mensaje |
|---|---|---|
| 1 | Alice | `Hola Bob` |
| 2 | Bob | `Hola Alice, te leo cifrado` |
| 3 | Alice | `El codigo secreto es 4321` |
| 4 | Bob | `Recibido, nadie mas lo ve` |
| 5 | Alice | `Tercer mensaje de Alice` |
| 6 | Bob | `Tercer mensaje de Bob` |

Con el primer mensaje, **comparar en voz alta**:
> "En Alice vemos el plaintext 'Hola Bob' y, debajo, el nonce, el ciphertext y el tag. Esos
> son los bytes que se escriben en el socket. En el proxy, que es lo que vería un atacante,
> aparecen exactamente los mismos bytes, sin texto legible. En Bob llegan esos bytes, se
> verifica el tag y **solo entonces** se muestra 'Hola Bob'."

Señalar también que el nonce cambia: el contador va 0, 1, 2…

### Parte 4 · Prueba de alteración (≈ 1 min)
7. **Alice:** `Transferir 100 colones a Bob` (es la 7.ª trama DATA).
> "El proxy cambió un solo byte del ciphertext, como se ve en rojo. Bob recibe la trama, el
> tag GCM no coincide y el mensaje se **rechaza**: no se muestra ningún texto."

8. **Bob:** `/alterar mensaje alterado por Bob`. Ahora el propio emisor simula la alteración
   y Alice lo rechaza.
9. **Alice:** `Este si llega bien`. Se acepta: la sesión sigue funcionando.

> "Esto demuestra que cifrar no basta: sin el tag, el atacante podría modificar el
> ciphertext sin que nadie lo notara."

### Parte 5 · Cierre y evidencia (≈ 40 s)
10. **Alice:** `/salir`. Bob muestra que Alice cerró la sesión. Pulsar Enter en Bob.
11. En cualquier terminal:
    ```bash
    grep -a -c "Hola Bob" captura.bin
    grep -a -c "4321" captura.bin
    grep -a -c "PRIVATE" captura.bin
    ```
    > "Todos dan 0: ni los mensajes ni las claves privadas cruzaron la red en claro."
12. (Opcional, 15 s) `python3 -m unittest test_securechat.py`. Muestra **OK** en las 9 pruebas.

### Parte 6 · Explicación final: asimétrico vs. simétrico (≈ 40 s)
> "La criptografía **asimétrica** solo se usa en el handshake. RSA-OAEP protege la clave de
> sesión con la pública de Bob, para que solo él la abra con su privada, y RSA-PSS firma esa
> clave para saber que viene de Alice. Así resolvemos cómo compartir un secreto sin haberlo
> compartido antes.
>
> La criptografía **simétrica**, AES-256-GCM, protege cada mensaje del chat, porque es mucho
> más rápida y además autentica: el tag detecta cualquier alteración. El nonce viaja en claro
> porque no es secreto, pero nunca se repite: usamos un contador con un prefijo distinto para
> cada dirección."

---
**Duración objetivo:** unos 5 min. Si se pasa de 6, recortar la Parte 1 y las pruebas
automáticas.
