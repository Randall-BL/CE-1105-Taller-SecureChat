# Lista de tareas: Taller SecureChat

## Hecho
- [x] Paso 1: chat TCP sobre localhost con dos instancias (`escuchar` / `conectar`). Cada lado
  muestra con quién está conectado (nombre, IP y puerto) y se pueden enviar varios mensajes.
- [x] Paso 2: par RSA-2048 por participante. La privada queda local con permisos 600 y nunca
  se imprime ni se envía.
- [x] Paso 3: handshake con RSA-OAEP (más firma PSS). La clave AES-256 es aleatoria y nunca va
  en claro. Al terminar se muestra "✓ SESIÓN SEGURA ESTABLECIDA".
- [x] Paso 4: AES-256-GCM con nonce contador + prefijo de dirección. El receptor verifica el
  tag antes de mostrar el texto.
- [x] Paso 5: chat bidireccional con colores (local / cifrado enviado / recibido) y `/salir`
  controlado.
- [x] Paso 6: prueba de alteración de dos formas: `/alterar` y `mitm_proxy.py --alterar N`.
- [x] README con instalación, ejecución, reproducción de la demo, protocolo y las 7 preguntas
  de cierre.
- [x] Informe en PDF (`Informe_SecureChat.pdf`) con capturas de una ejecución real.
- [x] 9 pruebas automáticas (`python3 -m unittest -v test_securechat.py`), todas en OK.
- [x] Guion del video (`GUION_VIDEO.md`).

## Te toca a ti
1. **Datos de portada.** En `Informe_SecureChat.tex` (líneas `% ====== COMPLETAR ======`) y en
   la cabecera de `README.md`:
   - carnés;
   - fecha de entrega;
   - confirmar si la pareja es Javier Tenorio. Si trabajas solo, bórralo.
2. **Grabar el video (4–6 min)** siguiendo `GUION_VIDEO.md`:
   - tres terminales visibles;
   - narración en ambas voces si es en pareja.
   Antes de grabar, haz `rm -rf claves/` para que se vea cómo se generan las claves.
3. **Subir el video** (YouTube no listado o Drive) y pegar el enlace en `\enlacevideo` del `.tex`.
4. **Recompilar el PDF:**
   ```bash
   pdflatex Informe_SecureChat.tex && pdflatex Informe_SecureChat.tex
   rm -f *.aux *.log *.toc *.out
   ```
5. *(Opcional)* Sustituir las imágenes de `capturas/` por capturas de pantalla reales, con
   los mismos nombres de archivo. Las actuales se generaron a partir de la salida real del
   programa.
6. **Empaquetar sin las claves privadas:**
   ```bash
   cd .. && rm -rf Entregable_Taller_SecureChat/claves Entregable_Taller_SecureChat/__pycache__ \
     && zip -r Entregable_Taller_SecureChat.zip Entregable_Taller_SecureChat
   ```
