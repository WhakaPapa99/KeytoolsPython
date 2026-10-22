
import io
import os
import tempfile
import unittest
from unittest.mock import patch

from cryptography import x509
from cryptography.x509.oid import NameOID

from mykeytool import (
    handle_genkeypair,
    handle_certreq,
    handle_list,
    handle_exportcert,
)


class TestIntegrationE2E(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.TemporaryDirectory()
        self.keystore_path = os.path.join(self.test_dir.name, "integration_keystore.jks")
        self.password = "SuperPassword2026!"
        self.alias = "servidor_produccion"

    def tearDown(self):
        self.test_dir.cleanup()

    def test_flujo_completo_e2e(self):
        with patch("getpass.getpass", return_value=self.password), \
             patch("builtins.input", side_effect=[
                 self.alias,
                 "Servidor Prod",
                 "Infraestructura",
                 "MiEmpresa",
                 "Valencia",
                 "Comunidad Valenciana",
                 "ES"
             ]), \
             patch("sys.stdout", new=io.StringIO()) as out_gen:
            code = handle_genkeypair(None, keystore_path=self.keystore_path)

        self.assertEqual(code, 0)
        self.assertTrue(os.path.exists(self.keystore_path))
        self.assertIn("generado y guardado con éxito", out_gen.getvalue())

        with patch("getpass.getpass", return_value=self.password), \
             patch("sys.stdout", new=io.StringIO()) as out_list:
            code = handle_list(None, keystore_path=self.keystore_path)

        self.assertEqual(code, 0)
        self.assertIn(self.alias, out_list.getvalue())

        csr_file = os.path.join(self.test_dir.name, f"{self.alias}.csr")
        with patch("getpass.getpass", return_value=self.password), \
             patch("builtins.input", return_value=self.alias), \
             patch("sys.stdout", new=io.StringIO()) as out_csr:
            with patch("mykeytool.DEFAULT_KEYSTORE", self.keystore_path):
                code = handle_certreq(None, keystore_path=self.keystore_path)

        self.assertEqual(code, 0)
        expected_csr = f"{self.alias}.csr"
        self.assertTrue(os.path.exists(expected_csr))

        with open(expected_csr, "rb") as f:
            csr_bytes = f.read()
        os.remove(expected_csr)

        csr = x509.load_pem_x509_csr(csr_bytes)
        self.assertTrue(csr.is_signature_valid)
        self.assertEqual(
            csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value,
            "Servidor Prod"
        )

        with patch("getpass.getpass", return_value=self.password), \
             patch("builtins.input", return_value=self.alias), \
             patch("sys.stdout", new=io.StringIO()) as out_exp:
            code = handle_exportcert(None, keystore_path=self.keystore_path)

        self.assertEqual(code, 0)
        expected_crt = f"{self.alias}.crt"
        self.assertTrue(os.path.exists(expected_crt))

        with open(expected_crt, "rb") as f:
            crt_bytes = f.read()
        os.remove(expected_crt)

        cert = x509.load_pem_x509_certificate(crt_bytes)
        self.assertEqual(
            cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value,
            "Servidor Prod"
        )

    def test_e2e_error_password_incorrecta(self):
        with patch("getpass.getpass", return_value=self.password), \
             patch("builtins.input", side_effect=[
                 self.alias, "CN", "OU", "O", "L", "ST", "ES"
             ]), \
             patch("sys.stdout", new=io.StringIO()):
            handle_genkeypair(None, keystore_path=self.keystore_path)

        with patch("getpass.getpass", return_value="password_erronea"), \
             patch("sys.stderr", new=io.StringIO()) as err_list:
            code = handle_list(None, keystore_path=self.keystore_path)

        self.assertEqual(code, 1)
        self.assertIn("Contraseña incorrecta", err_list.getvalue())

    def test_e2e_error_alias_duplicado(self):
        with patch("getpass.getpass", return_value=self.password), \
             patch("builtins.input", side_effect=[
                 self.alias, "CN", "OU", "O", "L", "ST", "ES"
             ]), \
             patch("sys.stdout", new=io.StringIO()):
            handle_genkeypair(None, keystore_path=self.keystore_path)

        with patch("getpass.getpass", return_value=self.password), \
             patch("builtins.input", side_effect=[
                 self.alias, "CN2", "OU2", "O2", "L2", "ST2", "ES"
             ]), \
             patch("sys.stdout", new=io.StringIO()), \
             patch("sys.stderr", new=io.StringIO()) as err_gen:
            code = handle_genkeypair(None, keystore_path=self.keystore_path)

        self.assertEqual(code, 1)
        self.assertIn("ya existe en el KeyStore", err_gen.getvalue())


if __name__ == "__main__":
    unittest.main()
