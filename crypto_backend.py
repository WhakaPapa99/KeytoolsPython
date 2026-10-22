
import datetime
import json
import os
from typing import Dict, List, Optional

from cryptography import x509
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.x509.oid import NameOID

from exceptions import (
    AliasDuplicadoError,
    AlmacenNoEncontradoError,
    KeyStoreError,
    PasswordIncorrectaError,
)

MAGIC_HEADER = b"PKS1"
SALT_SIZE = 16
NONCE_SIZE = 12
PBKDF2_ITERATIONS = 100_000


def generar_par_rsa(key_size: int = 2048, public_exponent: int = 65537) -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(
        public_exponent=public_exponent,
        key_size=key_size,
    )


def construir_distinguished_name(dn_data: Dict[str, str]) -> x509.Name:
    oid_map = {
        "CN": NameOID.COMMON_NAME,
        "OU": NameOID.ORGANIZATIONAL_UNIT_NAME,
        "O": NameOID.ORGANIZATION_NAME,
        "L": NameOID.LOCALITY_NAME,
        "ST": NameOID.STATE_OR_PROVINCE_NAME,
        "C": NameOID.COUNTRY_NAME,
    }
    attributes = []
    for key, oid in oid_map.items():
        val = dn_data.get(key, "").strip()
        if val:
            attributes.append(x509.NameAttribute(oid, val))

    if not attributes:
        attributes.append(x509.NameAttribute(NameOID.COMMON_NAME, "Keytool-Generated"))

    return x509.Name(attributes)


def generar_certificado_autofirmado(
    private_key: rsa.RSAPrivateKey,
    subject: x509.Name,
    days_valid: int = 365
) -> x509.Certificate:
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=days_valid))
        .sign(private_key, hashes.SHA256())
    )
    return cert


def _derivar_clave_aes(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def cifrar_almacen(store_dict: dict, password: str) -> bytes:
    plaintext = json.dumps(store_dict).encode("utf-8")
    salt = os.urandom(SALT_SIZE)
    aes_key = _derivar_clave_aes(password, salt)
    nonce = os.urandom(NONCE_SIZE)
    aesgcm = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return MAGIC_HEADER + salt + nonce + ciphertext


def descifrar_almacen(raw_bytes: bytes, password: str) -> dict:
    header_len = len(MAGIC_HEADER)
    min_len = header_len + SALT_SIZE + NONCE_SIZE + 16
    if len(raw_bytes) < min_len or not raw_bytes.startswith(MAGIC_HEADER):
        raise AlmacenNoEncontradoError("El archivo de almacén no tiene un formato válido o está dañado.")

    salt = raw_bytes[header_len : header_len + SALT_SIZE]
    nonce_start = header_len + SALT_SIZE
    nonce = raw_bytes[nonce_start : nonce_start + NONCE_SIZE]
    ciphertext = raw_bytes[nonce_start + NONCE_SIZE :]

    aes_key = _derivar_clave_aes(password, salt)
    aesgcm = AESGCM(aes_key)

    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    except InvalidTag:
        raise PasswordIncorrectaError("Contraseña incorrecta del almacén de claves.")

    try:
        store = json.loads(plaintext.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise AlmacenNoEncontradoError("El contenido del almacén está corrupto.")

    if not isinstance(store, dict):
        raise AlmacenNoEncontradoError("El contenido del almacén está corrupto.")
    return store


def cargar_almacen_existente(keystore_path: str, password: str) -> dict:
    if not os.path.isfile(keystore_path):
        raise AlmacenNoEncontradoError(f"El archivo de almacén '{keystore_path}' no se encuentra.")

    try:
        with open(keystore_path, "rb") as f:
            raw_bytes = f.read()
    except IOError as e:
        raise AlmacenNoEncontradoError(f"No se pudo leer el almacén: {e}")

    return descifrar_almacen(raw_bytes, password)


def guardar_almacen(keystore_path: str, password: str, store_dict: dict) -> None:
    encrypted_bytes = cifrar_almacen(store_dict, password)
    temp_path = f"{keystore_path}.tmp"
    with open(temp_path, "wb") as f:
        f.write(encrypted_bytes)
    os.replace(temp_path, keystore_path)



def crear_par_claves(
    keystore_path: str,
    password: str,
    alias: str,
    dn_data: Dict[str, str]
) -> None:
    if os.path.exists(keystore_path):
        store = cargar_almacen_existente(keystore_path, password)
        if alias in store:
            raise AliasDuplicadoError(f"El alias '{alias}' ya existe en el KeyStore.")
    else:
        store = {}

    private_key = generar_par_rsa(key_size=2048)

    subject = construir_distinguished_name(dn_data)
    cert = generar_certificado_autofirmado(private_key, subject)

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    cert_pem = cert.public_bytes(
        encoding=serialization.Encoding.PEM
    ).decode("utf-8")

    store[alias] = {
        "alias": alias,
        "private_key_pem": private_pem,
        "cert_pem": cert_pem,
        "dn_data": dn_data,
        "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "key_size": 2048,
        "algorithm": "RSA",
    }

    guardar_almacen(keystore_path, password, store)


def generar_csr(
    keystore_path: str,
    password: str,
    alias: str,
    output_file: str
) -> str:
    store = cargar_almacen_existente(keystore_path, password)
    if alias not in store:
        raise KeyStoreError(f"El alias '{alias}' no se encuentra en el KeyStore.")

    entry = store[alias]
    private_key = serialization.load_pem_private_key(
        entry["private_key_pem"].encode("utf-8"),
        password=None,
    )

    dn_data = entry.get("dn_data", {})
    subject = construir_distinguished_name(dn_data)

    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject)
        .sign(private_key, hashes.SHA256())
    )

    csr_pem_bytes = csr.public_bytes(serialization.Encoding.PEM)

    with open(output_file, "wb") as f:
        f.write(csr_pem_bytes)

    return output_file


def exportar_certificado(
    keystore_path: str,
    password: str,
    alias: str,
    output_file: str
) -> str:
    store = cargar_almacen_existente(keystore_path, password)
    if alias not in store:
        raise KeyStoreError(f"El alias '{alias}' no se encuentra en el KeyStore.")

    cert_pem = store[alias].get("cert_pem")
    if not cert_pem:
        raise KeyStoreError(f"No existe certificado para el alias '{alias}'.")

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(cert_pem)

    return output_file


def listar_alias(keystore_path: str, password: str) -> List[str]:
    store = cargar_almacen_existente(keystore_path, password)
    return list(store.keys())
