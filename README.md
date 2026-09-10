# crypto_tool — Herramienta de cifrado AES para archivos de texto plano

**Asignatura:** Fundamentos de Blockchain (BCY0010)
**Evaluación:** Evaluación Formativa N°2 — Encargo individual
**Indicadores de logro:** IL 1.1 (fundamentos de blockchain), IL 1.2 (criptografía aplicada)

## Descripción

Paquete básico en Python que cifra y descifra archivos de texto plano
(máximo 1 KB) utilizando el algoritmo **AES** a través de la librería
[PyCryptodome](https://pycryptodome.readthedocs.io/). Se ejecuta completamente
desde la línea de comandos (CLI).

## Estructura del repositorio

```
.
├── crypto_tool.py        # Programa principal (generación de llave, cifrado, descifrado)
├── requirements.txt      # Dependencias (pycryptodome)
├── README.md              # Este archivo
├── mensaje_prueba.txt     # Archivo de texto de prueba (< 1 KB)
└── capturas/              # Evidencia de ejecución (screenshots)
```

## Instalación

```bash
python3 -m venv venv
source venv/bin/activate      # En Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## Modo AES seleccionado: **EAX**

Se eligió el modo de operación **AES-EAX** (en vez de, por ejemplo, CBC) por
las siguientes razones:

1. **Cifrado autenticado (AEAD).** EAX no solo entrega confidencialidad, sino
   también un *tag* de autenticación que permite verificar que el mensaje no
   fue alterado y que fue cifrado con la llave correcta. Si el ciphertext es
   modificado, el descifrado falla explícitamente (`ValueError`) en lugar de
   devolver silenciosamente datos corruptos, como podría ocurrir con CBC sin
   un MAC adicional.
2. **No requiere padding manual.** A diferencia de CBC, EAX es un modo de
   flujo internamente, por lo que no es necesario implementar/gestionar
   padding (como PKCS7), reduciendo errores de implementación.
3. **Nonce de un solo uso.** PyCryptodome genera automáticamente un *nonce*
   aleatorio y seguro por cada operación de cifrado (`AES.new(key, AES.MODE_EAX)`),
   evitando la reutilización de keystream que ocurriría si se reutilizara un
   IV en modo CTR/CBC.
4. Es el modo recomendado en la propia documentación de PyCryptodome para
   casos de uso simples que requieren confidencialidad + integridad.

## Tamaño de llave utilizado: **32 bytes (256 bits) — AES-256**

Se usa el tamaño máximo soportado por el estándar AES (256 bits) para
maximizar el nivel de seguridad. La llave se genera con `get_random_bytes()`
de PyCryptodome, que utiliza el generador de números aleatorios criptográficamente
seguro (CSPRNG) del sistema operativo.

## Formato del archivo cifrado

El archivo de salida generado por `encrypt` concatena, en binario:

```
[nonce: 16 bytes] + [tag: 16 bytes] + [ciphertext: N bytes]
```

El nonce y el tag son necesarios (junto con la llave) para poder descifrar y
verificar la integridad del mensaje en la operación `decrypt`.

## Uso (CLI)

### 1. Generar una llave AES

```bash
python3 crypto_tool.py genkey --output key.bin --size 32
```

- `--output`: archivo donde se guarda la llave (por defecto `key.bin`).
- `--size`: tamaño de la llave en bytes: `16` (AES-128), `24` (AES-192) o `32` (AES-256, por defecto).

### 2. Cifrar el archivo de prueba

```bash
python3 crypto_tool.py encrypt --input mensaje_prueba.txt --key key.bin --output mensaje_cifrado.bin
```

Requisitos validados automáticamente:
- El archivo de entrada debe existir y no superar 1 KB (RF-01).
- Se imprime en consola el nonce, el tag y el ciphertext en hexadecimal.

### 3. Descifrar el archivo

```bash
python3 crypto_tool.py decrypt --input mensaje_cifrado.bin --key key.bin --output mensaje_descifrado.txt
```

- Se descifra usando la misma llave (`key.bin`).
- Se verifica automáticamente la integridad/autenticidad del mensaje (tag EAX).
- Se imprime en consola el texto recuperado y se guarda en `mensaje_descifrado.txt`,
  idéntico al `mensaje_prueba.txt` original.

### Ayuda

```bash
python3 crypto_tool.py --help
python3 crypto_tool.py encrypt --help
```

## Evidencia de ejecución

Las capturas de pantalla con la ejecución real de `genkey`, `encrypt` y
`decrypt` se encuentran en la carpeta [`capturas/`](./capturas).

## Bibliografía

- Arboledas Brihuega, D. (2017). *Criptografía sin secretos con Python*. RA-MA Editorial.
- Documentación PyCryptodome: <https://pycryptodome.readthedocs.io/>
