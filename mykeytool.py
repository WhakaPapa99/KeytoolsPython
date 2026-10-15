import argparse
import getpass
import os
import sys

import crypto_backend as default_crypto_backend
from exceptions import (
    AliasDuplicadoError,
    AlmacenNoEncontradoError,
    KeyStoreError,
    PasswordIncorrectaError,
)

DEFAULT_KEYSTORE = "keystore.jks"


def pedir_datos_dn():
    print("Introduzca los datos para el certificado:")
    cn = input("¿Cuáles son su nombre y apellidos? (CN): ").strip()
    ou = input("¿Cuál es el nombre de su unidad organizativa? (OU): ").strip()
    o = input("¿Cuál es el nombre de su organización? (O): ").strip()
    l = input("¿Cuál es el nombre de su ciudad o localidad? (L): ").strip()
    st = input("¿Cuál es el nombre de su estado o provincia? (ST): ").strip()
    c = input("¿Cuál es el código de dos letras de su país? (C): ").strip()
    return {
        "CN": cn,
        "OU": ou,
        "O": o,
        "L": l,
        "ST": st,
        "C": c
    }


def handle_genkeypair(args, crypto_backend=None, keystore_path=DEFAULT_KEYSTORE):
    """Maneja el flujo de generación de par de claves."""
    try:
        password = getpass.getpass("Introduzca la contraseña del KeyStore: ")
        if not password:
            print("Error: La contraseña no puede estar vacía.", file=sys.stderr)
            return 1

        alias = input("Introduzca el alias para la clave: ").strip()
        if not alias:
            print("Error: El alias no puede estar vacío.", file=sys.stderr)
            return 1

        dn_data = pedir_datos_dn()

        backend = crypto_backend if crypto_backend is not None else default_crypto_backend
        backend.crear_par_claves(
            keystore_path=keystore_path,
            password=password,
            alias=alias,
            dn_data=dn_data
        )

        print(f"Par de claves RSA de 2048 bits generado y guardado con éxito bajo el alias '{alias}'.")
        return 0

    except AliasDuplicadoError:
        print(f"Error: El alias '{alias}' ya existe en el KeyStore.", file=sys.stderr)
        return 1
    except PasswordIncorrectaError:
        print("Error: Contraseña incorrecta.", file=sys.stderr)
        return 1
    except KeyStoreError as e:
        print(f"Error en el almacén: {e}", file=sys.stderr)
        return 1


def handle_certreq(args, crypto_backend=None, keystore_path=DEFAULT_KEYSTORE):
    """Maneja el flujo de solicitud de firma de certificado (CSR)."""
    try:
        if not os.path.exists(keystore_path):
            raise AlmacenNoEncontradoError(f"El archivo del almacén '{keystore_path}' no se encuentra o está dañado.")

        password = getpass.getpass("Introduzca la contraseña del KeyStore: ")
        if not password:
            print("Error: La contraseña no puede estar vacía.", file=sys.stderr)
            return 1

        alias = input("Introduzca el alias de la clave: ").strip()
        if not alias:
            print("Error: El alias no puede estar vacío.", file=sys.stderr)
            return 1

        output_file = f"{alias}.csr"

        backend = crypto_backend if crypto_backend is not None else default_crypto_backend
        backend.generar_csr(
            keystore_path=keystore_path,
            password=password,
            alias=alias,
            output_file=output_file
        )
        print(f"Solicitud de firma de certificado (CSR) generada en '{output_file}'.")
        return 0

    except AlmacenNoEncontradoError:
        print("Error: El archivo del almacén no se encuentra o está dañado.", file=sys.stderr)
        return 1
    except PasswordIncorrectaError:
        print("Error: Contraseña incorrecta.", file=sys.stderr)
        return 1
    except KeyStoreError as e:
        print(f"Error al generar CSR: {e}", file=sys.stderr)
        return 1


def handle_list(args, crypto_backend=None, keystore_path=DEFAULT_KEYSTORE):
    """Ampliación: Lista los alias guardados en el KeyStore."""
    try:
        if not os.path.exists(keystore_path):
            raise AlmacenNoEncontradoError(f"El archivo del almacén '{keystore_path}' no se encuentra o está dañado.")

        password = getpass.getpass("Introduzca la contraseña del KeyStore: ")
        if not password:
            print("Error: La contraseña no puede estar vacía.", file=sys.stderr)
            return 1

        backend = crypto_backend if crypto_backend is not None else default_crypto_backend
        aliases = backend.listar_alias(keystore_path, password)

        if not aliases:
            print("El KeyStore está vacío (0 entradas).")
        else:
            print("\nAlias en el KeyStore:")
            for a in aliases:
                print(f" - {a}")
        return 0
    except PasswordIncorrectaError:
        print("Error: Contraseña incorrecta.", file=sys.stderr)
        return 1
    except AlmacenNoEncontradoError:
        print("Error: El archivo del almacén no se encuentra o está dañado.", file=sys.stderr)
        return 1


def handle_exportcert(args, crypto_backend=None, keystore_path=DEFAULT_KEYSTORE):
    """Ampliación: Extrae el certificado X.509 en formato PEM."""
    try:
        if not os.path.exists(keystore_path):
            raise AlmacenNoEncontradoError(f"El archivo del almacén '{keystore_path}' no se encuentra o está dañado.")

        password = getpass.getpass("Introduzca la contraseña del KeyStore: ")
        if not password:
            print("Error: La contraseña no puede estar vacía.", file=sys.stderr)
            return 1

        alias = input("Introduzca el alias del certificado a exportar: ").strip()
        if not alias:
            print("Error: El alias no puede estar vacío.", file=sys.stderr)
            return 1

        output_file = f"{alias}.crt"

        backend = crypto_backend if crypto_backend is not None else default_crypto_backend
        backend.exportar_certificado(
            keystore_path=keystore_path,
            password=password,
            alias=alias,
            output_file=output_file
        )
        print(f"Certificado exportado con éxito en '{output_file}'.")
        return 0

    except AlmacenNoEncontradoError:
        print("Error: El archivo del almacén no se encuentra o está dañado.", file=sys.stderr)
        return 1
    except PasswordIncorrectaError:
        print("Error: Contraseña incorrecta.", file=sys.stderr)
        return 1
    except KeyStoreError as e:
        print(f"Error al exportar certificado: {e}", file=sys.stderr)
        return 1


def crear_parser():
    parser = argparse.ArgumentParser(
        prog="mykeytool.py",
        description="Simulador CLI de Java Keytool en Python.",
        add_help=False
    )

    parser.add_argument(
        "-h", "--help",
        action="help",
        help="Muestra esta ayuda y sale."
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--genkeypair", "--genkey",
        dest="genkeypair",
        action="store_true",
        help="Genera un par de claves RSA de 2048 bits y lo guarda en el KeyStore."
    )
    group.add_argument(
        "--certreq",
        action="store_true",
        help="Extrae una solicitud de firma de certificado (CSR) en formato PEM."
    )
    group.add_argument(
        "--list",
        action="store_true",
        help="(Ampliación) Muestra todos los alias contenidos en el KeyStore."
    )
    group.add_argument(
        "--exportcert",
        action="store_true",
        help="(Ampliación) Exporta el certificado X.509 en formato PEM."
    )
    return parser


def main():
    parser = crear_parser()
    args = parser.parse_args()

    if args.genkeypair:
        sys.exit(handle_genkeypair(args))
    elif args.certreq:
        sys.exit(handle_certreq(args))
    elif args.list:
        sys.exit(handle_list(args))
    elif args.exportcert:
        sys.exit(handle_exportcert(args))


if __name__ == "__main__":
    main()