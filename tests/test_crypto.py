
import os
import tempfile
import unittest

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

import crypto_backend
from exceptions import (
    AliasDuplicadoError,
    AlmacenNoEncontradoError,
    KeyStoreError,
    PasswordIncorrectaError,
)


class TestCryptoBackend(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.TemporaryDirectory()
        self.keystore_path = os.path.join(self.test_dir.name, "test_keystore.jks")
        self.password = "ClaveSegura123!"
        self.dn_data = {
            "CN": "Servidor Seguro",
            "OU": "Seguridad",
            "O": "Mi Empresa SL",
            "L": "Valencia",
            "ST": "Valencia",
            "C": "ES",
        }

    def tearDown(self):
        self.test_dir.cleanup()

    def test_generacion_rsa_2048(self):
        key = crypto_backend.generar_par_rsa(key_size=2048)
        self.assertIsInstance(key, rsa.RSAPrivateKey)
        self.assertEqual(key.key_size, 2048)
        self.assertEqual(key.public_key().public_numbers().e, 65537)

    def test_persistencia_keystore_y_recuperacion(self):
        crypto_backend.crear_par_claves(
            keystore_path=self.keystore_path,
            password=self.password,
            alias="mi_clave",
            dn_data=self.dn_data,
        )

        self.assertTrue(os.path.exists(self.keystore_path))

        with open(self.keystore_path, "rb") as f:
            raw = f.read()
        self.assertTrue(raw.startswith(b"PKS1"))
        self.assertNotIn(b"Servidor Seguro", raw)
        self.assertNotIn(b"BEGIN PRIVATE KEY", raw)

        store = crypto_backend.cargar_almacen_existente(self.keystore_path, self.password)
        self.assertIn("mi_clave", store)
        self.assertIn("private_key_pem", store["mi_clave"])
        self.assertIn("cert_pem", store["mi_clave"])
        self.assertEqual(store["mi_clave"]["dn_data"]["CN"], "Servidor Seguro")

    def test_persistencia_password_incorrecta(self):
        crypto_backend.crear_par_claves(
            keystore_path=self.keystore_path,
            password=self.password,
            alias="mi_clave",
            dn_data=self.dn_data,
        )

        with self.assertRaises(PasswordIncorrectaError):
            crypto_backend.cargar_almacen_existente(self.keystore_path, "password_falsa")

    def test_error_alias_duplicado(self):
        crypto_backend.crear_par_claves(
            keystore_path=self.keystore_path,
            password=self.password,
            alias="clave_repetida",
            dn_data=self.dn_data,
        )

        with self.assertRaises(AliasDuplicadoError):
            crypto_backend.crear_par_claves(
                keystore_path=self.keystore_path,
                password=self.password,
                alias="clave_repetida",
                dn_data=self.dn_data,
            )

    def test_almacen_inexistente(self):
        ruta_falsa = os.path.join(self.test_dir.name, "no_existe.jks")
        with self.assertRaises(AlmacenNoEncontradoError):
            crypto_backend.cargar_almacen_existente(ruta_falsa, self.password)

    def test_almacen_corrupto(self):
        corrupt_path = os.path.join(self.test_dir.name, "corrupto.jks")
        with open(corrupt_path, "wb") as f:
            f.write(b"BASURA_NO_VALIDA_DE_LONGITUD_CORTA")

        with self.assertRaises(AlmacenNoEncontradoError):
            crypto_backend.cargar_almacen_existente(corrupt_path, self.password)

    def test_generacion_csr_pem(self):
        crypto_backend.crear_par_claves(
            keystore_path=self.keystore_path,
            password=self.password,
            alias="servidor_web",
            dn_data=self.dn_data,
        )

        csr_output = os.path.join(self.test_dir.name, "servidor_web.csr")
        crypto_backend.generar_csr(
            keystore_path=self.keystore_path,
            password=self.password,
            alias="servidor_web",
            output_file=csr_output,
        )

        self.assertTrue(os.path.exists(csr_output))

        with open(csr_output, "rb") as f:
            csr_bytes = f.read()

        self.assertTrue(csr_bytes.startswith(b"-----BEGIN CERTIFICATE REQUEST-----"))

        csr = x509.load_pem_x509_csr(csr_bytes)
        self.assertTrue(csr.is_signature_valid)
        cn = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        self.assertEqual(cn, "Servidor Seguro")

    def test_exportar_certificado_pem(self):
        crypto_backend.crear_par_claves(
            keystore_path=self.keystore_path,
            password=self.password,
            alias="servidor_web",
            dn_data=self.dn_data,
        )

        crt_output = os.path.join(self.test_dir.name, "servidor_web.crt")
        crypto_backend.exportar_certificado(
            keystore_path=self.keystore_path,
            password=self.password,
            alias="servidor_web",
            output_file=crt_output,
        )

        self.assertTrue(os.path.exists(crt_output))

        with open(crt_output, "rb") as f:
            crt_bytes = f.read()

        self.assertTrue(crt_bytes.startswith(b"-----BEGIN CERTIFICATE-----"))
        cert = x509.load_pem_x509_certificate(crt_bytes)
        self.assertEqual(
            cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value,
            "Servidor Seguro"
        )

    def test_listar_alias(self):
        crypto_backend.crear_par_claves(
            keystore_path=self.keystore_path,
            password=self.password,
            alias="alias1",
            dn_data=self.dn_data,
        )
        crypto_backend.crear_par_claves(
            keystore_path=self.keystore_path,
            password=self.password,
            alias="alias2",
            dn_data=self.dn_data,
        )

        aliases = crypto_backend.listar_alias(self.keystore_path, self.password)
        self.assertEqual(set(aliases), {"alias1", "alias2"})


if __name__ == "__main__":
    unittest.main()
