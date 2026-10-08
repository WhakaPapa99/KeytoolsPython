import argparse
import getpass
import sys
from exceptions import (
    KeyStoreError,
    PasswordIncorrectaError,
    AliasDuplicadoError,
    AlmacenNoEncontradoError,
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

def handle_genkeypair(args, crypto_backend=None):
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

        if crypto_backend:
            crypto_backend.crear_par_claves(
                keystore_path=DEFAULT_KEYSTORE,
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

def handle_certreq(args, crypto_backend=None):
    try:
        password = getpass.getpass("Introduzca la contraseña del KeyStore: ")
        alias = input("Introduzca el alias de la clave: ").strip()
        if not alias:
            print("Error: El alias no puede estar vacío.", file=sys.stderr)
            return 1

        output_file = f"{alias}.csr"

        if crypto_backend:
            crypto_backend.generar_csr(
                keystore_path=DEFAULT_KEYSTORE,
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

def handle_list(args, crypto_backend=None):
    try:
        password = getpass.getpass("Introduzca la contraseña del KeyStore: ")
        if crypto_backend:
            aliases = crypto_backend.listar_alias(DEFAULT_KEYSTORE, password)
            print("\nAlias en el KeyStore:")
            for a in aliases:
                print(f" - {a}")
        else:
            print("Operación completada.")
        return 0
    except PasswordIncorrectaError:
        print("Error: Contraseña incorrecta.", file=sys.stderr)
        return 1
    except AlmacenNoEncontradoError:
        print("Error: El archivo del almacén no se encuentra o está dañado.", file=sys.stderr)
        return 1

def crear_parser():
    parser = argparse.ArgumentParser(
        prog="mykeytool.py",
        description="Simulador CLI de Java Keytool en Python."
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

if __name__ == "__main__":
    main()