# Simulador CLI de Java Keytool en Python

Proyecto para la asignatura de Seguridad y Alta Disponibilidad (SPS). Simulación en línea de comandos (CLI) de las funcionalidades esenciales de la herramienta oficial `keytool` de Java.

---

## 👥 Integrantes del Proyecto
* **Integrante 1 (Rama A - Interfaz y Validaciones):** Marc Ayala Silverio
* **Integrante 2 (Rama B - Criptografía y Persistencia):** *[Nombre del compañero]*

---

## 📋 Estructura y Responsabilidad de esta Rama (`marc`)

Esta rama implementa la **Rama A: Interfaz de Línea de Comandos (CLI) y Control de Excepciones**:
* **Gestión de Argumentos:** Procesador de comandos mediante `argparse` con exclusión mutua para `--genkeypair` (con soporte para el alias `--genkey`), `--certreq` y `--list`.
* **Asistente de Prompts Interactivos:** 
  * Captura de contraseña segura mediante `getpass` (sin eco en consola).
  * Solicitud de datos del titular (**Distinguished Name - DN**): CN, OU, O, L, ST, C.
  * Solicitud de alias y validación de campos obligatorios.
* **Control Robusto de Excepciones:** Captura controlada de errores con mensajes claros dirigidos a `stderr` sin mostrar trazas de error inesperadas (*tracebacks*):
  * `PasswordIncorrectaError` (acceso denegado por credenciales erróneas).
  * `AliasDuplicadoError` (intento de sobrescribir un alias existente).
  * `AlmacenNoEncontradoError` (archivo de almacén no localizado o corrupto).
* **Verificación de Almacén:** Comprueba la existencia física del almacén antes de pedir contraseña en `--list` y `--certreq`, avisando si no existe.
* **Ampliación (+30% nota):** Comando `--list` implementado para listar los alias guardados en el almacén de claves.
* **Nombre del Script:** Implementado bajo `mykeytool.py` según la especificación obligatoria del enunciado.

---

## ⚙️ Instalación de Dependencias

Se recomienda el uso de un entorno virtual para aislar las dependencias:

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
* `cryptography>=42.0.0` (Librería criptográfica)
* `pytest>=8.0.0` (Framework de testing)
* `pytest-mock>=3.12.0` (Soporte de mocks para pytest)

---

## 🚀 Guía de Uso de la CLI

El script se ejecuta mediante `python mykeytool.py` (o `python3 mykeytool.py` según el entorno).

### 1. Muestreo de Ayuda (`--help`)
Muestra la lista de opciones disponibles, parámetros y descripción sintáctica:
```bash
python mykeytool.py --help
```
**Salida esperada:**
```text
usage: mykeytool.py [-h] (--genkeypair | --certreq | --list)

Simulador CLI de Java Keytool en Python.

options:
  -h, --help            show this help message and exit
  --genkeypair, --genkey
                        Genera un par de claves RSA de 2048 bits y lo guarda en el KeyStore.
  --certreq             Extrae una solicitud de firma de certificado (CSR) en formato PEM.
  --list                (Ampliación) Muestra todos los alias contenidos en el KeyStore.
```

---

### 2. Generación de Par de Claves y Almacén (`--genkeypair` o `--genkey`)
Inicia el asistente para solicitar credenciales y los campos del Distinguished Name (DN):
```bash
python mykeytool.py --genkeypair
```
*(También admite `python mykeytool.py --genkey`)*

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

### 3. Extracción de Solicitud de Certificado CSR (`--certreq`)
Recupera la clave privada del almacén y genera un archivo `.csr` en formato PEM:
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

### 4. Ampliación: Listado de Claves (`--list`)
Muestra los alias almacenados en el KeyStore (comprueba primero que el almacén exista):
```bash
python mykeytool.py --list
```
**Ejemplo de sesión en consola:**
```text
Introduzca la contraseña del KeyStore: ********

Alias en el KeyStore:
 - mi_servidor
 - backup_key
```

---

## 🧪 Matriz de Pruebas Unitarias

Las pruebas se ejecutan con `pytest` o con el módulo nativo `unittest`. Simulan las interacciones de consola con `unittest.mock` para garantizar el aislamiento de la CLI.

Para lanzar las pruebas:
```bash
pytest -v
# o bien:
python -m unittest discover tests -v
```

### Resultados de la Batería de Tests (16/16 PASSED)

| ID | Caso de Prueba | Entrada / Condición Simulada | Comportamiento Esperado | Estado |
|---|---|---|---|:---:|
| **T01** | `test_parser_ayuda` | `--help` | Retorna código 0 y muestra los comandos obligatorios y de ampliación | ✅ PASSED |
| **T02** | `test_parser_alias_genkey` | `--genkey` y `--genkeypair` | Ambos parámetros activan la misma bandera `genkeypair=True` | ✅ PASSED |
| **T03** | `test_parser_certreq_y_list` | `--certreq`, `--list` | Se reconocen de forma mutuamente excluyente | ✅ PASSED |
| **T04** | `test_genkeypair_captura_datos_exito` | Contraseña válida, alias y 6 campos de DN | Envía los datos exactos a `crear_par_claves` y retorna 0 | ✅ PASSED |
| **T05** | `test_genkeypair_password_vacia` | Contraseña en blanco | Emite mensaje de error a stderr y retorna código 1 | ✅ PASSED |
| **T06** | `test_genkeypair_alias_vacio` | Alias en blanco | Emite mensaje de error a stderr y retorna código 1 | ✅ PASSED |
| **T07** | `test_error_alias_duplicado` | Backend lanza `AliasDuplicadoError` | Rechaza la operación indicando que el alias ya existe (retorna 1) | ✅ PASSED |
| **T08** | `test_error_password_incorrecta_genkeypair` | Backend lanza `PasswordIncorrectaError` | Informa "Contraseña incorrecta" a stderr sin tracebacks | ✅ PASSED |
| **T09** | `test_certreq_exito` | Contraseña y alias válidos con almacén existente | Invoca `generar_csr` con `<alias>.csr` y retorna 0 | ✅ PASSED |
| **T10** | `test_certreq_alias_vacio` | Alias vacío en certreq | Deniega la operación y retorna código 1 | ✅ PASSED |
| **T11** | `test_error_password_incorrecta_certreq` | Backend lanza `PasswordIncorrectaError` | Informa "Contraseña incorrecta" a stderr sin tracebacks | ✅ PASSED |
| **T12** | `test_error_almacen_no_encontrado_certreq` | Almacén no existe en disco antes de certreq | Informa que el almacén no existe o está dañado sin pedir password (retorna 1) | ✅ PASSED |
| **T13** | `test_list_exito` | Backend devuelve lista de alias | Imprime en pantalla cada alias y retorna código 0 | ✅ PASSED |
| **T14** | `test_list_vacio` | Almacén existente sin claves | Informa que el KeyStore está vacío (0 entradas) | ✅ PASSED |
| **T15** | `test_list_error_password` | Backend lanza `PasswordIncorrectaError` en `--list` | Informa error de contraseña y retorna código 1 | ✅ PASSED |
| **T16** | `test_list_error_almacen_inexistente` | Almacén no existe en disco | Informa error directamente sin pedir contraseña (retorna 1) | ✅ PASSED |

---

## 🔗 Integración con la Rama B (`rama-b-crypto`)

Para realizar la integración final en `main`:
1. La Rama B debe implementar el módulo criptográfico (`crypto_manager.py` o `keystore.py`) con las siguientes firmas:
   * `crear_par_claves(keystore_path, password, alias, dn_data)`
   * `generar_csr(keystore_path, password, alias, output_file)`
   * `listar_alias(keystore_path, password)`
2. Lanzar las excepciones definidas en [`exceptions.py`](exceptions.py) en caso de fallos.
3. En [`mykeytool.py`](mykeytool.py), importar el módulo de la Rama B y pasarlo como `crypto_backend` en la llamada de `main()`.