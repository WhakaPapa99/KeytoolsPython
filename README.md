# Simulador CLI de Java Keytool en Python

Simulación completa en línea de comandos (CLI) de las funcionalidades esenciales de la herramienta oficial `keytool` de Java, integrando tanto la interfaz de usuario como la criptografía real y la persistencia cifrada.

---

## 📁 Arquitectura Modular del Código

El repositorio está organizado en módulos desacoplados y limpios de código muerto:

```text
KeytoolsPython/
├── mykeytool.py          # Script ejecutable principal (CLI, argparse y orquestación)
├── crypto_backend.py     # Lógica criptográfica (RSA 2048, AES-GCM, PBKDF2, X.509, CSR)
├── exceptions.py         # Jerarquía de excepciones personalizadas del KeyStore
├── requirements.txt      # Dependencias del proyecto (cryptography, pytest, pytest-mock)
├── .gitignore            # Filtro para entornos (.venv), cachés y artefactos generados
└── tests/
    ├── test_cli.py          # 20 tests: Interfaz de comandos, prompts y mocks de excepciones
    ├── test_crypto.py       # 9 tests: Criptografía RSA, cifrado AES-GCM, integridad y CSR
    └── test_integration.py  # 3 tests: Ciclo de vida completo End-to-End con archivos reales
```

---

## ⚙️ Instalación de Dependencias

Se recomienda ejecutar en un entorno virtual de Python:

```bash
# 1. Crear el entorno virtual (si no está creado)
python -m venv .venv

# 2. Activar el entorno virtual
# En Windows (PowerShell):
.venv\Scripts\Activate.ps1
# En Linux / macOS / MSYS2:
source .venv/bin/activate

# 3. Instalar las dependencias
pip install -r requirements.txt
```

### Contenido de `requirements.txt`:
* `cryptography>=42.0.0`
* `pytest>=8.0.0`
* `pytest-mock>=3.12.0`

---

## 🚀 Guía de Uso de la CLI

El script ejecutable oficial es `mykeytool.py`.

### 1. Menú de Ayuda (`--help`)
Muestra la lista de opciones disponibles, parámetros y descripción sintáctica:
```bash
python mykeytool.py --help
```
**Salida de consola:**
```text
usage: mykeytool.py [-h] (--genkeypair | --certreq | --list | --exportcert)

Simulador CLI de Java Keytool en Python.

options:
  -h, --help            Muestra este mensage de ayuda
  --genkeypair, --genkey
                        Genera un par de claves RSA de 2048 bits y lo guarda en el KeyStore.
  --certreq             Extrae una solicitud de firma de certificado (CSR) en formato PEM.
  --list                (Ampliación) Muestra todos los alias contenidos en el KeyStore.
  --exportcert          (Ampliación) Exporta el certificado X.509 en formato PEM.
```

---

### 2. Generación de Par de Claves y Almacén (`--genkeypair` o `--genkey`)
Genera un par de claves RSA de 2048 bits, construye el Distinguished Name (DN) X.500, genera un certificado autofirmado y almacena todo cifrado con AES-256-GCM en `keystore.jks`:
```bash
python mykeytool.py --genkeypair
```
*(También se puede invocar con el alias `python mykeytool.py --genkey`)*

**Ejemplo de sesión en consola:**
```text
Introduzca la contraseña del KeyStore: ********
Introduzca el alias para la clave: mi_servidor
Introduzca los datos para el certificado:
¿Cuáles son su nombre y apellidos? (CN): Marc Ayala
¿Cuál es el nombre de su unidad organizativa? (OU): Ciberseguridad
¿Cuál es el nombre de su organización? (O): IES
¿Cuál es el nombre de su ciudad o localidad? (L): Valencia
¿Cuál es el nombre de su estado o provincia? (ST): Valencia
¿Cuál es el código de dos letras de su país? (C): ES
Par de claves RSA de 2048 bits generado y guardado con éxito bajo el alias 'mi_servidor'.
```

---

### 3. Extracción de Solicitud de Firma de Certificado CSR (`--certreq`)
Descifra el almacén con la contraseña, recupera la clave privada del alias y genera un archivo `.csr` firmado con SHA-256 en estándar PEM:
```bash
python mykeytool.py --certreq
```
**Ejemplo de sesión en consola:**
```text
Introduzca la contraseña del KeyStore: ********
Introduzca el alias de la clave: mi_servidor
Solicitud de firma de certificado (CSR) generada en 'mi_servidor.csr'.
```

---

### 4. Ampliación: Listado de Alias del KeyStore (`--list`)
Descifra el almacén y enumera todas las entradas/alias existentes:
```bash
python mykeytool.py --list
```
**Ejemplo de sesión en consola:**
```text
Introduzca la contraseña del KeyStore: ********

Alias en el KeyStore:
 - mi_servidor
```

---

### 5. Ampliación: Exportación de Certificado X.509 (`--exportcert`)
Exporta el certificado público asociado al alias en formato PEM (`<alias>.crt`):
```bash
python mykeytool.py --exportcert
```
**Ejemplo de sesión en consola:**
```text
Introduzca la contraseña del KeyStore: ********
Introduzca el alias del certificado a exportar: mi_servidor
Certificado exportado con éxito en 'mi_servidor.crt'.
```

---

## 🛡️ Gestión de Excepciones y Escenarios Anómalos (Apartado 3.2)

El sistema captura y gestiona de forma amigable todas las anomalías sin lanzar *tracebacks*:
* **Contraseña Incorrecta:** Si se introduce una contraseña errónea al abrir el KeyStore, el descifrado AES-256-GCM detecta la discrepancia en el tag de autenticación y emite:
  ```text
  Error: Contraseña incorrecta.
  ```
* **Alias Duplicado:** Si se intenta generar un par con un alias que ya existe dentro del KeyStore, se deniega la operación:
  ```text
  Error: El alias 'mi_servidor' ya existe en el KeyStore.
  ```
* **Almacén Inexistente o Dañado:** Si no existe el archivo del almacén o ha sido manipulado, no solicita contraseñas inútilmente y avisa:
  ```text
  Error: El archivo del almacén 'keystore.jks' no se encuentra o está dañado.
  ```

---

## 🧪 Matriz Completa de Pruebas Unitarias y de Integración (32/32 PASSED)

Para ejecutar la batería completa de pruebas:
```bash
pytest -v
# o mediante el módulo estándar:
python -m unittest discover tests -v
```

### 1. Pruebas de Interfaz y CLI (`tests/test_cli.py` - 20 tests)
| ID | Caso de Prueba | Condición Evaluada | Resultado |
|---|---|---|:---:|
| **CLI-01** | `test_parser_ayuda` | `--help` muestra comandos obligatorios y de ampliación | ✅ PASSED |
| **CLI-02** | `test_parser_alias_genkey` | `--genkey` activa el mismo flag que `--genkeypair` | ✅ PASSED |
| **CLI-03** | `test_parser_comandos_mutuamente_excluyentes` | Exclusión mutua entre comandos | ✅ PASSED |
| **CLI-04** | `test_genkeypair_captura_datos_exito` | Envío íntegro de campos DN al backend | ✅ PASSED |
| **CLI-05** | `test_genkeypair_password_vacia` | Rechazo de contraseña vacía | ✅ PASSED |
| **CLI-06** | `test_genkeypair_alias_vacio` | Rechazo de alias vacío | ✅ PASSED |
| **CLI-07** | `test_error_alias_duplicado` | Captura controlada de `AliasDuplicadoError` | ✅ PASSED |
| **CLI-08** | `test_error_password_incorrecta_genkeypair` | Captura de `PasswordIncorrectaError` en genkeypair | ✅ PASSED |
| **CLI-09** | `test_certreq_exito` | Invocación de generación de CSR | ✅ PASSED |
| **CLI-10** | `test_certreq_alias_vacio` | Validación de alias obligatorio en certreq | ✅ PASSED |
| **CLI-11** | `test_error_password_incorrecta_certreq` | Captura de contraseña errónea en certreq | ✅ PASSED |
| **CLI-12** | `test_error_almacen_no_encontrado_certreq` | Almacén ausente en certreq | ✅ PASSED |
| **CLI-13** | `test_list_exito` | Listado de claves existentes | ✅ PASSED |
| **CLI-14** | `test_list_vacio` | Aviso de almacén sin entradas (0 entradas) | ✅ PASSED |
| **CLI-15** | `test_list_error_password` | Contraseña incorrecta en list | ✅ PASSED |
| **CLI-16** | `test_list_error_almacen_inexistente` | Almacén ausente en list | ✅ PASSED |
| **CLI-17** | `test_exportcert_exito` | Invocación de exportación de certificado | ✅ PASSED |
| **CLI-18** | `test_exportcert_alias_vacio` | Validación de alias obligatorio en exportcert | ✅ PASSED |
| **CLI-19** | `test_exportcert_error_password` | Contraseña incorrecta en exportcert | ✅ PASSED |
| **CLI-20** | `test_exportcert_error_almacen_inexistente` | Almacén ausente en exportcert | ✅ PASSED |

### 2. Pruebas Criptográficas y de Persistencia (`tests/test_crypto.py` - 9 tests)
| ID | Caso de Prueba | Condición Evaluada | Resultado |
|---|---|---|:---:|
| **CRYPTO-01** | `test_generacion_rsa_2048` | Clave RSA exactamente de 2048 bits con e=65537 | ✅ PASSED |
| **CRYPTO-02** | `test_persistencia_keystore_y_recuperacion` | Cifrado y descifrado seguro en disco con AES-GCM | ✅ PASSED |
| **CRYPTO-03** | `test_persistencia_password_incorrecta` | Fallo de autenticación en AES-GCM con contraseña incorrecta | ✅ PASSED |
| **CRYPTO-04** | `test_error_alias_duplicado` | Detección de colisión de alias | ✅ PASSED |
| **CRYPTO-05** | `test_almacen_inexistente` | Detección de archivo no encontrado | ✅ PASSED |
| **CRYPTO-06** | `test_almacen_corrupto` | Detección de cabecera mágica corrupta o archivo alterado | ✅ PASSED |
| **CRYPTO-07** | `test_generacion_csr_pem` | Firma válida y formato PEM X.509 de la CSR generada | ✅ PASSED |
| **CRYPTO-08** | `test_exportar_certificado_pem` | Extracción y validación de certificado X.509 autofirmado | ✅ PASSED |
| **CRYPTO-09** | `test_listar_alias` | Listado múltiple de claves descifradas | ✅ PASSED |

### 3. Pruebas de Integración End-to-End (`tests/test_integration.py` - 3 tests)
| ID | Caso de Prueba | Condición Evaluada | Resultado |
|---|---|---|:---:|
| **E2E-01** | `test_flujo_completo_e2e` | Ciclo completo: genkeypair -> list -> certreq -> exportcert con criptografía y archivos reales | ✅ PASSED |
| **E2E-02** | `test_e2e_error_password_incorrecta` | Rechazo real de acceso al almacén en disco con contraseña errónea | ✅ PASSED |
| **E2E-03** | `test_e2e_error_alias_duplicado` | Denegación real de sobrescritura de alias sobre almacén existente | ✅ PASSED |