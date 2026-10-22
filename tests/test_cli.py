import io
import sys
import unittest
from unittest.mock import patch, MagicMock

from mykeytool import (
    crear_parser,
    handle_genkeypair,
    handle_certreq,
    handle_list,
    handle_exportcert,
)
from exceptions import (
    AliasDuplicadoError,
    PasswordIncorrectaError,
    AlmacenNoEncontradoError,
    KeyStoreError,
)


class TestCLI(unittest.TestCase):


    def test_parser_ayuda(self):
        parser = crear_parser()
        with self.assertRaises(SystemExit) as cm:
            with patch("sys.stdout", new=io.StringIO()) as fake_out:
                parser.parse_args(["--help"])
        self.assertEqual(cm.exception.code, 0)
        output = fake_out.getvalue()
        self.assertIn("--genkeypair", output)
        self.assertIn("--genkey", output)
        self.assertIn("--certreq", output)
        self.assertIn("--list", output)
        self.assertIn("--exportcert", output)

    def test_parser_alias_genkey(self):
        parser = crear_parser()
        args_alias = parser.parse_args(["--genkey"])
        self.assertTrue(args_alias.genkeypair)

        args_full = parser.parse_args(["--genkeypair"])
        self.assertTrue(args_full.genkeypair)

    def test_parser_comandos_mutuamente_excluyentes(self):
        parser = crear_parser()
        self.assertTrue(parser.parse_args(["--certreq"]).certreq)
        self.assertTrue(parser.parse_args(["--list"]).list)
        self.assertTrue(parser.parse_args(["--exportcert"]).exportcert)


    @patch("getpass.getpass", return_value="clave123")
    @patch("builtins.input", side_effect=[
        "mi_servidor",
        "Marc",
        "Sistemas",
        "IES",
        "Valencia",
        "Valencia",
        "ES"
    ])
    def test_genkeypair_captura_datos_exito(self, mock_input, mock_getpass):
        mock_backend = MagicMock()
        with patch("sys.stdout", new=io.StringIO()) as fake_out:
            exit_code = handle_genkeypair(None, crypto_backend=mock_backend)

        self.assertEqual(exit_code, 0)
        mock_backend.crear_par_claves.assert_called_once()
        self.assertIn("generado y guardado con éxito", fake_out.getvalue())

    @patch("getpass.getpass", return_value="")
    def test_genkeypair_password_vacia(self, mock_getpass):
        with patch("sys.stderr", new=io.StringIO()) as fake_err:
            exit_code = handle_genkeypair(None, crypto_backend=MagicMock())
        self.assertEqual(exit_code, 1)
        self.assertIn("no puede estar vacía", fake_err.getvalue())

    @patch("getpass.getpass", return_value="clave123")
    @patch("builtins.input", return_value="")
    def test_genkeypair_alias_vacio(self, mock_input, mock_getpass):
        with patch("sys.stderr", new=io.StringIO()) as fake_err:
            exit_code = handle_genkeypair(None, crypto_backend=MagicMock())
        self.assertEqual(exit_code, 1)
        self.assertIn("no puede estar vacío", fake_err.getvalue())


    @patch("getpass.getpass", return_value="clave123")
    @patch("builtins.input", side_effect=["alias_dup", "A", "B", "C", "D", "E", "ES"])
    def test_error_alias_duplicado(self, mock_input, mock_getpass):
        mock_backend = MagicMock()
        mock_backend.crear_par_claves.side_effect = AliasDuplicadoError("Duplicado")

        with patch("sys.stdout", new=io.StringIO()), patch("sys.stderr", new=io.StringIO()) as fake_err:
            exit_code = handle_genkeypair(None, crypto_backend=mock_backend)

        self.assertEqual(exit_code, 1)
        self.assertIn("ya existe en el KeyStore", fake_err.getvalue())

    @patch("getpass.getpass", return_value="clave_erronea")
    @patch("builtins.input", side_effect=["mi_alias", "A", "B", "C", "D", "E", "ES"])
    def test_error_password_incorrecta_genkeypair(self, mock_input, mock_getpass):
        mock_backend = MagicMock()
        mock_backend.crear_par_claves.side_effect = PasswordIncorrectaError("Password mal")

        with patch("sys.stdout", new=io.StringIO()), patch("sys.stderr", new=io.StringIO()) as fake_err:
            exit_code = handle_genkeypair(None, crypto_backend=mock_backend)

        self.assertEqual(exit_code, 1)
        self.assertIn("Contraseña incorrecta", fake_err.getvalue())


    @patch("os.path.exists", return_value=True)
    @patch("getpass.getpass", return_value="clave123")
    @patch("builtins.input", return_value="mi_alias")
    def test_certreq_exito(self, mock_input, mock_getpass, mock_exists):
        mock_backend = MagicMock()
        with patch("sys.stdout", new=io.StringIO()) as fake_out:
            exit_code = handle_certreq(None, crypto_backend=mock_backend)

        self.assertEqual(exit_code, 0)
        mock_backend.generar_csr.assert_called_once()
        self.assertIn("Solicitud de firma de certificado (CSR) generada", fake_out.getvalue())

    @patch("os.path.exists", return_value=True)
    @patch("getpass.getpass", return_value="clave123")
    @patch("builtins.input", return_value="")
    def test_certreq_alias_vacio(self, mock_input, mock_getpass, mock_exists):
        with patch("sys.stderr", new=io.StringIO()) as fake_err:
            exit_code = handle_certreq(None, crypto_backend=MagicMock())
        self.assertEqual(exit_code, 1)
        self.assertIn("no puede estar vacío", fake_err.getvalue())

    @patch("os.path.exists", return_value=True)
    @patch("getpass.getpass", return_value="clave_erronea")
    @patch("builtins.input", return_value="mi_alias")
    def test_error_password_incorrecta_certreq(self, mock_input, mock_getpass, mock_exists):
        mock_backend = MagicMock()
        mock_backend.generar_csr.side_effect = PasswordIncorrectaError("Password incorrecta")

        with patch("sys.stderr", new=io.StringIO()) as fake_err:
            exit_code = handle_certreq(None, crypto_backend=mock_backend)

        self.assertEqual(exit_code, 1)
        self.assertIn("Contraseña incorrecta", fake_err.getvalue())

    @patch("os.path.exists", return_value=False)
    def test_error_almacen_no_encontrado_certreq(self, mock_exists):
        with patch("sys.stderr", new=io.StringIO()) as fake_err:
            exit_code = handle_certreq(None, crypto_backend=MagicMock())

        self.assertEqual(exit_code, 1)
        self.assertIn("no se encuentra o está dañado", fake_err.getvalue())


    @patch("os.path.exists", return_value=True)
    @patch("getpass.getpass", return_value="clave123")
    def test_list_exito(self, mock_getpass, mock_exists):
        mock_backend = MagicMock()
        mock_backend.listar_alias.return_value = ["servidor_web", "firma_digital"]

        with patch("sys.stdout", new=io.StringIO()) as fake_out:
            exit_code = handle_list(None, crypto_backend=mock_backend)

        self.assertEqual(exit_code, 0)
        output = fake_out.getvalue()
        self.assertIn("servidor_web", output)
        self.assertIn("firma_digital", output)

    @patch("os.path.exists", return_value=True)
    @patch("getpass.getpass", return_value="clave123")
    def test_list_vacio(self, mock_getpass, mock_exists):
        mock_backend = MagicMock()
        mock_backend.listar_alias.return_value = []

        with patch("sys.stdout", new=io.StringIO()) as fake_out:
            exit_code = handle_list(None, crypto_backend=mock_backend)

        self.assertEqual(exit_code, 0)
        self.assertIn("El KeyStore está vacío (0 entradas)", fake_out.getvalue())

    @patch("os.path.exists", return_value=True)
    @patch("getpass.getpass", return_value="clave_erronea")
    def test_list_error_password(self, mock_getpass, mock_exists):
        mock_backend = MagicMock()
        mock_backend.listar_alias.side_effect = PasswordIncorrectaError("Password mal")

        with patch("sys.stderr", new=io.StringIO()) as fake_err:
            exit_code = handle_list(None, crypto_backend=mock_backend)

        self.assertEqual(exit_code, 1)
        self.assertIn("Contraseña incorrecta", fake_err.getvalue())

    @patch("os.path.exists", return_value=False)
    def test_list_error_almacen_inexistente(self, mock_exists):
        with patch("sys.stderr", new=io.StringIO()) as fake_err:
            exit_code = handle_list(None, crypto_backend=MagicMock())

        self.assertEqual(exit_code, 1)
        self.assertIn("no se encuentra o está dañado", fake_err.getvalue())


    @patch("os.path.exists", return_value=True)
    @patch("getpass.getpass", return_value="clave123")
    @patch("builtins.input", return_value="mi_alias")
    def test_exportcert_exito(self, mock_input, mock_getpass, mock_exists):
        mock_backend = MagicMock()
        with patch("sys.stdout", new=io.StringIO()) as fake_out:
            exit_code = handle_exportcert(None, crypto_backend=mock_backend)

        self.assertEqual(exit_code, 0)
        mock_backend.exportar_certificado.assert_called_once()
        self.assertIn("Certificado exportado con éxito", fake_out.getvalue())

    @patch("os.path.exists", return_value=True)
    @patch("getpass.getpass", return_value="clave123")
    @patch("builtins.input", return_value="")
    def test_exportcert_alias_vacio(self, mock_input, mock_getpass, mock_exists):
        with patch("sys.stderr", new=io.StringIO()) as fake_err:
            exit_code = handle_exportcert(None, crypto_backend=MagicMock())
        self.assertEqual(exit_code, 1)
        self.assertIn("no puede estar vacío", fake_err.getvalue())

    @patch("os.path.exists", return_value=True)
    @patch("getpass.getpass", return_value="clave_erronea")
    @patch("builtins.input", return_value="mi_alias")
    def test_exportcert_error_password(self, mock_input, mock_getpass, mock_exists):
        mock_backend = MagicMock()
        mock_backend.exportar_certificado.side_effect = PasswordIncorrectaError("Password mal")

        with patch("sys.stderr", new=io.StringIO()) as fake_err:
            exit_code = handle_exportcert(None, crypto_backend=mock_backend)

        self.assertEqual(exit_code, 1)
        self.assertIn("Contraseña incorrecta", fake_err.getvalue())

    @patch("os.path.exists", return_value=False)
    def test_exportcert_error_almacen_inexistente(self, mock_exists):
        with patch("sys.stderr", new=io.StringIO()) as fake_err:
            exit_code = handle_exportcert(None, crypto_backend=MagicMock())

        self.assertEqual(exit_code, 1)
        self.assertIn("no se encuentra o está dañado", fake_err.getvalue())


if __name__ == "__main__":
    unittest.main()