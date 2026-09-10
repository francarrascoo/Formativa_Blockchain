#!/usr/bin/env python3
"""
crypto_tool.py
================

Paquete básico de encriptación de archivos de texto plano usando AES
(a través de PyCryptodome).

Asignatura : Fundamentos de Blockchain (BCY0010)
Evaluación : Evaluación Formativa N°2 - Encargo individual
Indicadores: IL 1.1 (fundamentos de blockchain) / IL 1.2 (criptografía aplicada)

Funcionalidad (requisitos funcionales del encargo):
    RF-01: Recibe como input un archivo de texto plano (máximo 1 KB).
    RF-02: Genera una llave criptográfica válida para el algoritmo AES.
    RF-03: Cifra el contenido del archivo y devuelve el texto cifrado (ciphertext).
    RF-04: Descifra el texto cifrado utilizando la misma llave, recuperando el
           texto original.
    RF-05: Se ejecuta completamente desde la línea de comandos (CLI).

Modo de operación AES elegido: EAX
---------------------------------
Se eligió AES en modo EAX (Encrypt-then-MAC, AEAD) porque:
  1. Es un modo de "cifrado autenticado" (AEAD): además de confidencialidad
     entrega un "tag" que permite verificar integridad y autenticidad del
     mensaje. Si el ciphertext es alterado, el descifrado falla en lugar de
     devolver silenciosamente datos corruptos (a diferencia de CBC/CTR).
  2. No requiere padding manual (a diferencia de CBC), lo que reduce la
     superficie de errores de implementación.
  3. Usa un nonce (nunce/IV) de un solo uso por mensaje, generado de forma
     aleatoria y segura, evitando reutilización de keystream.
  4. Es el modo recomendado por la propia documentación de PyCryptodome para
     casos de uso simples que requieren confidencialidad + integridad.

Tamaño de llave: 32 bytes (256 bits) -> AES-256, el nivel de seguridad más
alto soportado por el estándar AES.
"""

import argparse
import os
import sys

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# --------------------------------------------------------------------------- #
# Constantes
# --------------------------------------------------------------------------- #
MAX_INPUT_SIZE_BYTES = 1024   # RF-01: máximo 1 KB de entrada
AES_KEY_SIZE_BYTES = 32       # AES-256 (valores válidos: 16, 24 o 32)
NONCE_SIZE_BYTES = 16         # Tamaño de nonce por defecto del modo EAX
TAG_SIZE_BYTES = 16           # Tamaño del tag de autenticación en modo EAX


# --------------------------------------------------------------------------- #
# RF-02: Generación de llave AES
# --------------------------------------------------------------------------- #
def generar_llave(ruta_salida: str, tamano_bytes: int = AES_KEY_SIZE_BYTES) -> bytes:
    """
    Genera una llave AES criptográficamente segura usando get_random_bytes()
    y la almacena en un archivo binario independiente para que pueda ser
    reutilizada posteriormente en operaciones de cifrado/descifrado.

    Args:
        ruta_salida: Ruta del archivo donde se guardará la llave (binario).
        tamano_bytes: Tamaño de la llave en bytes. Debe ser 16, 24 o 32
                      (128, 192 o 256 bits respectivamente).

    Returns:
        La llave generada, en bytes.
    """
    if tamano_bytes not in (16, 24, 32):
        raise ValueError("El tamaño de la llave debe ser 16, 24 o 32 bytes (AES).")

    # get_random_bytes() usa el generador de números aleatorios seguro del
    # sistema operativo (CSPRNG), por lo que es apto para uso criptográfico.
    llave = get_random_bytes(tamano_bytes)

    with open(ruta_salida, "wb") as archivo_llave:
        archivo_llave.write(llave)

    print(f"[OK] Llave AES-{tamano_bytes * 8} generada y guardada en: {ruta_salida}")
    print(f"     Llave (hex): {llave.hex()}")
    return llave


def cargar_llave(ruta_llave: str) -> bytes:
    """Carga una llave AES previamente generada desde un archivo binario."""
    if not os.path.isfile(ruta_llave):
        raise FileNotFoundError(f"No se encontró el archivo de llave: {ruta_llave}")

    with open(ruta_llave, "rb") as archivo_llave:
        llave = archivo_llave.read()

    if len(llave) not in (16, 24, 32):
        raise ValueError(
            f"La llave cargada tiene un tamaño inválido para AES: {len(llave)} bytes."
        )
    return llave


# --------------------------------------------------------------------------- #
# RF-01 + RF-03: Lectura de archivo de entrada y cifrado
# --------------------------------------------------------------------------- #
def leer_texto_plano(ruta_entrada: str) -> bytes:
    """
    Lee un archivo de texto plano y valida que no supere el tamaño máximo
    permitido (RF-01: máximo 1 KB).
    """
    if not os.path.isfile(ruta_entrada):
        raise FileNotFoundError(f"No se encontró el archivo de entrada: {ruta_entrada}")

    with open(ruta_entrada, "rb") as archivo:
        contenido = archivo.read()

    if len(contenido) == 0:
        raise ValueError("El archivo de entrada está vacío.")

    if len(contenido) > MAX_INPUT_SIZE_BYTES:
        raise ValueError(
            f"El archivo de entrada supera el tamaño máximo permitido "
            f"({len(contenido)} bytes > {MAX_INPUT_SIZE_BYTES} bytes)."
        )

    return contenido


def cifrar_archivo(ruta_entrada: str, ruta_llave: str, ruta_salida: str) -> bytes:
    """
    Cifra el contenido de un archivo de texto plano usando AES en modo EAX.

    Formato del archivo de salida (todo en binario, concatenado):
        [nonce (16 bytes)] + [tag (16 bytes)] + [ciphertext]

    Guardar nonce y tag junto al ciphertext es necesario porque ambos se
    requieren, junto con la llave, para poder descifrar y verificar la
    integridad del mensaje.

    Returns:
        El ciphertext (bytes), sin nonce ni tag.
    """
    texto_plano = leer_texto_plano(ruta_entrada)
    llave = cargar_llave(ruta_llave)

    # AES.MODE_EAX genera automáticamente un nonce aleatorio si no se indica
    # uno explícitamente.
    cifrador = AES.new(llave, AES.MODE_EAX)
    ciphertext, tag = cifrador.encrypt_and_digest(texto_plano)

    with open(ruta_salida, "wb") as archivo_salida:
        archivo_salida.write(cifrador.nonce)  # 16 bytes
        archivo_salida.write(tag)              # 16 bytes
        archivo_salida.write(ciphertext)

    print(f"[OK] Archivo cifrado correctamente -> {ruta_salida}")
    print(f"     Tamaño texto plano : {len(texto_plano)} bytes")
    print(f"     Nonce (hex)        : {cifrador.nonce.hex()}")
    print(f"     Tag (hex)          : {tag.hex()}")
    print(f"     Ciphertext (hex)   : {ciphertext.hex()}")

    return ciphertext


# --------------------------------------------------------------------------- #
# RF-04: Descifrado
# --------------------------------------------------------------------------- #
def descifrar_archivo(ruta_entrada: str, ruta_llave: str, ruta_salida: str) -> bytes:
    """
    Descifra un archivo generado por cifrar_archivo(), utilizando la misma
    llave AES, y recupera el texto original. Verifica además la integridad
    y autenticidad del mensaje mediante el tag EAX (si el archivo fue
    alterado, la verificación falla y se lanza una excepción).
    """
    if not os.path.isfile(ruta_entrada):
        raise FileNotFoundError(f"No se encontró el archivo cifrado: {ruta_entrada}")

    llave = cargar_llave(ruta_llave)

    with open(ruta_entrada, "rb") as archivo:
        nonce = archivo.read(NONCE_SIZE_BYTES)
        tag = archivo.read(TAG_SIZE_BYTES)
        ciphertext = archivo.read()

    descifrador = AES.new(llave, AES.MODE_EAX, nonce=nonce)
    texto_plano = descifrador.decrypt_and_verify(ciphertext, tag)

    with open(ruta_salida, "wb") as archivo_salida:
        archivo_salida.write(texto_plano)

    print(f"[OK] Archivo descifrado correctamente -> {ruta_salida}")
    print(f"     Integridad/autenticidad verificada (tag EAX OK).")
    print(f"     Texto recuperado:\n{texto_plano.decode('utf-8')}")

    return texto_plano


# --------------------------------------------------------------------------- #
# RF-05: Interfaz de línea de comandos (CLI)
# --------------------------------------------------------------------------- #
def construir_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="crypto_tool.py",
        description="Paquete básico de encriptación AES de archivos de texto plano "
                     "(Evaluación Formativa N°2 - BCY0010 Fundamentos de Blockchain).",
    )
    subparsers = parser.add_subparsers(dest="comando", required=True)

    # --- genkey ---
    p_genkey = subparsers.add_parser("genkey", help="Genera una nueva llave AES.")
    p_genkey.add_argument(
        "-o", "--output", default="key.bin",
        help="Ruta del archivo donde guardar la llave (por defecto: key.bin)."
    )
    p_genkey.add_argument(
        "-s", "--size", type=int, default=AES_KEY_SIZE_BYTES, choices=(16, 24, 32),
        help="Tamaño de la llave en bytes: 16 (AES-128), 24 (AES-192) o 32 (AES-256). "
             "Por defecto: 32."
    )

    # --- encrypt ---
    p_encrypt = subparsers.add_parser("encrypt", help="Cifra un archivo de texto plano.")
    p_encrypt.add_argument("-i", "--input", required=True, help="Archivo de texto plano a cifrar.")
    p_encrypt.add_argument("-k", "--key", default="key.bin", help="Archivo de llave AES.")
    p_encrypt.add_argument("-o", "--output", default="mensaje_cifrado.bin",
                            help="Archivo de salida cifrado (por defecto: mensaje_cifrado.bin).")

    # --- decrypt ---
    p_decrypt = subparsers.add_parser("decrypt", help="Descifra un archivo previamente cifrado.")
    p_decrypt.add_argument("-i", "--input", required=True, help="Archivo cifrado a descifrar.")
    p_decrypt.add_argument("-k", "--key", default="key.bin", help="Archivo de llave AES.")
    p_decrypt.add_argument("-o", "--output", default="mensaje_descifrado.txt",
                            help="Archivo de salida con el texto recuperado "
                                 "(por defecto: mensaje_descifrado.txt).")

    return parser


def main() -> None:
    parser = construir_parser()
    args = parser.parse_args()

    try:
        if args.comando == "genkey":
            generar_llave(args.output, args.size)
        elif args.comando == "encrypt":
            cifrar_archivo(args.input, args.key, args.output)
        elif args.comando == "decrypt":
            descifrar_archivo(args.input, args.key, args.output)
    except Exception as error:
        print(f"[ERROR] {error}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
