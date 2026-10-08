import io
import sys
import unittest
from unittest.mock import patch, MagicMock

from mykeytool import (
    crear_parser,
    handle_genkeypair,
    handle_certreq,
    handle_list,
)
from exceptions import (
    AliasDuplicadoError,
    PasswordIncorrectaError,
    AlmacenNoEncontradoError,
    KeyStoreError,
)


class TestCLI(unittest.TestCase):

    # --- 1. Tests de Argumentos y Ayuda ---

    def test_parser_ayuda(self):
        """Verifica que --help muestra sintaxis y los comandos disponibles."""
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

    def test_parser_alias_genkey(self):
        """Verifica que --genkey funciona como alias de --genkeypair."""
        parser = crear_parser()
        args_alias = parser.parse_args(["--genkey"])
        self.assertTrue(args_alias.genkeypair)

        args_full = parser.parse_args(["--genkeypair"])
        self.assertTrue(args_full.genkeypair)

    def test_parser_certreq_y_list(self):
        """Verifica el reconocimiento individual de --certreq y --list."""
        parser = crear_parser()
        args_certreq = parser.parse_args(["--certreq"])
        self.assertTrue(args_certreq.certreq)

        args_list = parser.parse_args(["--list"])
        self.assertTrue(args_list.list)

    # --- 2. Tests de Flujo e Inputs de --genkeypair ---

    @patch("getpass.getpass", return_value="clave123")
    @patch("builtins.input", side_effect=[
        "mi_servidor",  # Alias
        "Marc",         # CN
        "Sistemas",     # OU
        "IES",          # O
        "Valencia",     # L
        "Valencia",     # ST
        "ES"            # C
    ])
    def test_genkeypair_captura_datos_exito(self, mock_input, mock_getpass):
        """Simula entradas completas y comprueba envío correcto al backend."""
        mock_backend = MagicMock()
        with patch("sys.stdout", new=io.StringIO()) as fake_out:
            exit_code = handle_genkeypair(None, crypto_backend=mock_backend)

        self.assertEqual(exit_code, 0)
        mock_backend.crear_par_claves.assert_called_once()
        self.assertIn("generado y guardado con éxito", fake_out.getvalue())

    @patch("getpass.getpass", return_value="")
    def test_genkeypair_password_vacia(self, mock_getpass):
        """Comprueba validación cuando la contraseña está vacía."""
        with patch("sys.stderr", new=io.StringIO()) as fake_err:
            exit_code = handle_genkeypair(None)
        self.assertEqual(exit_code, 1)
        self.assertIn("no puede estar vacía", fake_err.getvalue())

    @patch("getpass.getpass", return_value="clave123")
    @patch("builtins.input", return_value="")
    def test_genkeypair_alias_vacio(self, mock_input, mock_getpass):
        """Comprueba validación cuando el alias está vacío."""
        with patch("sys.stderr", new=io.StringIO()) as fake_err:
            exit_code = handle_genkeypair(None)
        self.assertEqual(exit_code, 1)
        self.assertIn("no puede estar vacío", fake_err.getvalue())

    # --- 3. Tests de Control de Excepciones en --genkeypair ---

    @patch("getpass.getpass", return_value="clave123")
    @patch("builtins.input", side_effect=["alias_dup", "A", "B", "C", "D", "E", "ES"])
    def test_error_alias_duplicado(self, mock_input, mock_getpass):
        """Comprueba que un alias duplicado muestra mensaje amigable y no crashea."""
        mock_backend = MagicMock()
        mock_backend.crear_par_claves.side_effect = AliasDuplicadoError("Duplicado")

        with patch("sys.stdout", new=io.StringIO()), patch("sys.stderr", new=io.StringIO()) as fake_err:
            exit_code = handle_genkeypair(None, crypto_backend=mock_backend)

        self.assertEqual(exit_code, 1)
        self.assertIn("ya existe en el KeyStore", fake_err.getvalue())

    @patch("getpass.getpass", return_value="clave_erronea")
    @patch("builtins.input", side_effect=["mi_alias", "A", "B", "C", "D", "E", "ES"])
    def test_error_password_incorrecta_genkeypair(self, mock_input, mock_getpass):
        """Comprueba rechazo amigable de contraseña incorrecta al generar clave."""
        mock_backend = MagicMock()
        mock_backend.crear_par_claves.side_effect = PasswordIncorrectaError("Password mal")

        with patch("sys.stdout", new=io.StringIO()), patch("sys.stderr", new=io.StringIO()) as fake_err:
            exit_code = handle_genkeypair(None, crypto_backend=mock_backend)

        self.assertEqual(exit_code, 1)
        self.assertIn("Contraseña incorrecta", fake_err.getvalue())

    # --- 4. Tests de Flujo y Errores en --certreq ---

    @patch("getpass.getpass", return_value="clave123")
    @patch("builtins.input", return_value="mi_alias")
    def test_certreq_exito(self, mock_input, mock_getpass):
        """Verifica generación de CSR exitosa."""
        mock_backend = MagicMock()
        with patch("sys.stdout", new=io.StringIO()) as fake_out:
            exit_code = handle_certreq(None, crypto_backend=mock_backend)

        self.assertEqual(exit_code, 0)
        mock_backend.generar_csr.assert_called_once()
        self.assertIn("Solicitud de firma de certificado (CSR) generada", fake_out.getvalue())

    @patch("getpass.getpass", return_value="clave123")
    @patch("builtins.input", return_value="")
    def test_certreq_alias_vacio(self, mock_input, mock_getpass):
        """Comprueba validación de alias vacío en certreq."""
        with patch("sys.stderr", new=io.StringIO()) as fake_err:
            exit_code = handle_certreq(None)
        self.assertEqual(exit_code, 1)
        self.assertIn("no puede estar vacío", fake_err.getvalue())

    @patch("getpass.getpass", return_value="clave_erronea")
    @patch("builtins.input", return_value="mi_alias")
    def test_error_password_incorrecta_certreq(self, mock_input, mock_getpass):
        """Comprueba rechazo amigable de contraseña en certreq."""
        mock_backend = MagicMock()
        mock_backend.generar_csr.side_effect = PasswordIncorrectaError("Password incorrecta")

        with patch("sys.stderr", new=io.StringIO()) as fake_err:
            exit_code = handle_certreq(None, crypto_backend=mock_backend)

        self.assertEqual(exit_code, 1)
        self.assertIn("Contraseña incorrecta", fake_err.getvalue())

    @patch("getpass.getpass", return_value="clave123")
    @patch("builtins.input", return_value="mi_alias")
    def test_error_almacen_no_encontrado_certreq(self, mock_input, mock_getpass):
        """Comprueba informe amigable cuando el almacén no existe o está dañado."""
        mock_backend = MagicMock()
        mock_backend.generar_csr.side_effect = AlmacenNoEncontradoError("No existe archivo")

        with patch("sys.stderr", new=io.StringIO()) as fake_err:
            exit_code = handle_certreq(None, crypto_backend=mock_backend)

        self.assertEqual(exit_code, 1)
        self.assertIn("no se encuentra o está dañado", fake_err.getvalue())

    # --- 5. Tests de Ampliación (--list) ---

    @patch("getpass.getpass", return_value="clave123")
    def test_list_exito(self, mock_getpass):
        """Verifica que --list enumera los alias existentes."""
        mock_backend = MagicMock()
        mock_backend.listar_alias.return_value = ["servidor_web", "firma_digital"]

        with patch("sys.stdout", new=io.StringIO()) as fake_out:
            exit_code = handle_list(None, crypto_backend=mock_backend)

        self.assertEqual(exit_code, 0)
        output = fake_out.getvalue()
        self.assertIn("servidor_web", output)
        self.assertIn("firma_digital", output)

    @patch("getpass.getpass", return_value="clave_erronea")
    def test_list_error_password(self, mock_getpass):
        """Comprueba gestión de contraseña incorrecta en --list."""
        mock_backend = MagicMock()
        mock_backend.listar_alias.side_effect = PasswordIncorrectaError("Password mal")

        with patch("sys.stderr", new=io.StringIO()) as fake_err:
            exit_code = handle_list(None, crypto_backend=mock_backend)

        self.assertEqual(exit_code, 1)
        self.assertIn("Contraseña incorrecta", fake_err.getvalue())

    @patch("getpass.getpass", return_value="clave123")
    def test_list_error_almacen(self, mock_getpass):
        """Comprueba gestión de almacén inexistente en --list."""
        mock_backend = MagicMock()
        mock_backend.listar_alias.side_effect = AlmacenNoEncontradoError("No existe")

        with patch("sys.stderr", new=io.StringIO()) as fake_err:
            exit_code = handle_list(None, crypto_backend=mock_backend)

        self.assertEqual(exit_code, 1)
        self.assertIn("no se encuentra o está dañado", fake_err.getvalue())


if __name__ == "__main__":
    unittest.main()