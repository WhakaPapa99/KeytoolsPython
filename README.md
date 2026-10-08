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
* **Ampliación (+30% nota):** Comando `--list` implementado para listar los alias guardados en el almacén de claves.

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

El script se puede ejecutar mediante `python mykeytool.py`.

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
Muestra los alias almacenados en el KeyStore:
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