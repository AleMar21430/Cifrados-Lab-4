# Dependencies
- Python
```
pip install -r requirements.txt
```

# Run

## Backend:
```bash
cd Backend
uvicorn Backend:app
```

## Frontend:
```bash
python Frontend.py
```


# Secure File Manager

Secure File Manager es una aplicación de gestión de archivos segura que permite a los usuarios registrarse, iniciar sesión, subir, descargar y verificar archivos. El sistema implementa encriptación asimétrica (RSA) y firma digital para garantizar la confidencialidad e integridad de los archivos. La arquitectura se divide en dos partes principales: un frontend basado en PySide6 para la interfaz gráfica de usuario (GUI) y un backend desarrollado con FastAPI que expone los endpoints de la API.

---

## Tabla de Contenidos

- [Características](#características)
- [Tecnologías Utilizadas](#tecnologías-utilizadas)
- [Estructura del Proyecto](#estructura-del-proyecto)
- [Instalación y Configuración](#instalación-y-configuración)
- [Uso de la Aplicación](#uso-de-la-aplicación)
  - [Frontend](#frontend)
  - [Backend](#backend)
- [Endpoints de la API](#endpoints-de-la-api)
- [Encriptación y Firma Digital](#encriptación-y-firma-digital)
- [Notas de Seguridad](#notas-de-seguridad)

---

## Características

- **Registro y Autenticación de Usuarios:**  
  Los usuarios pueden registrarse y autenticarse mediante JWT (JSON Web Tokens) usando FastAPI y OAuth2.

- **Gestión de Archivos:**  
  Permite la subida de archivos de forma encriptada, descarga de archivos encriptados y verificación de integridad mediante firmas digitales.

- **Encriptación Asimétrica con RSA:**  
  Utiliza RSA para encriptar y desencriptar archivos. La encriptación se realiza en trozos debido al tamaño limitado de RSA.

- **Firma Digital:**  
  Los archivos se pueden firmar digitalmente y posteriormente verificarse para garantizar que el archivo no haya sido modificado.

- **Interfaz Gráfica (GUI):**  
  Una interfaz amigable desarrollada con PySide6 que permite interactuar con la aplicación de forma sencilla.

---

## Tecnologías Utilizadas

- **Python 3.x**
- **FastAPI:** Framework web para construir la API.
- **Uvicorn:** Servidor ASGI para ejecutar FastAPI.
- **PySide6:** Para la interfaz gráfica (GUI) del frontend.
- **Requests:** Librería para realizar peticiones HTTP desde el frontend.
- **PyCryptodome:** Para la generación y manejo de claves RSA en el módulo de encriptación.
- **Cryptography:** Para la generación y verificación de firmas digitales.
- **JWT y OAuth2:** Para la autenticación y la emisión de tokens.
- **Pickle:** Para almacenar de forma simple la base de datos en disco (DB.bin).

---

## Estructura del Proyecto

El proyecto se divide en cuatro módulos principales:

- **Frontend.py:**  
  Contiene la lógica de la interfaz gráfica. Permite al usuario registrarse, iniciar sesión, subir archivos (tanto normales como firmados), descargar archivos y verificar la integridad de los mismos. Gestiona la comunicación con el backend a través de peticiones HTTP.

- **Backend.py:**  
  Implementa la API REST usando FastAPI. Gestiona el registro y autenticación de usuarios, así como las operaciones de almacenamiento, descarga y verificación de archivos. Utiliza JWT para la autorización y almacena la información de archivos, usuarios y claves en un diccionario que se persiste en un fichero binario usando pickle.

- **Encrypt.py:**  
  Provee funciones para generar claves RSA, encriptar y desencriptar datos. La encriptación se realiza en bloques (chunks) para adaptarse al tamaño limitado del cifrado RSA.

- **Sign.py:**  
  Implementa funciones para firmar digitalmente archivos y para verificar dichas firmas. Emplea el módulo `cryptography` de Python junto con el esquema de padding PSS y el algoritmo de hash SHA256.

Cada módulo se comunica de manera colaborativa para proporcionar una solución completa de gestión y seguridad de archivos.

---

## Instalación y Configuración

1. **Clonar el repositorio:**
    ```bash
    git clone https://ruta-del-repositorio.git
    cd ruta-del-repositorio
    ```

2. **Crear y activar un entorno virtual (opcional pero recomendado):**
    ```bash
    python -m venv venv
    source venv/bin/activate  # En Windows: venv\Scripts\activate
    ```

3. **Instalar las dependencias necesarias:**
    Asegúrate de tener un archivo `requirements.txt` con las siguientes dependencias (o instálalas manualmente):
    ```bash
    pip install fastapi uvicorn pyside6 requests pycryptodome cryptography passlib[bcrypt] python-jose
    ```

4. **Ejecutar el backend:**
    ```bash
    uvicorn Backend:app --reload
    ```
    Esto iniciará el servidor FastAPI en `http://127.0.0.1:8000`.

5. **Ejecutar el frontend:**
    ```bash
    python Frontend.py
    ```
    La aplicación de escritorio se abrirá y podrás interactuar con la API.

---

## Uso de la Aplicación

### Frontend

El módulo **Frontend.py** ofrece una interfaz gráfica que facilita las siguientes acciones:

- **Registro y Login:**  
  Permite registrar un nuevo usuario. Durante el registro se generan claves RSA (pública y privada), que se almacenan en el directorio `./Keys`. Después de registrarse, el usuario inicia sesión y se autentica a través del backend.

- **Listado de Archivos:**  
  Una vez autenticado, se muestra una lista de archivos disponibles en el servidor. Los archivos firmados se resaltan en verde.

- **Subida de Archivos:**  
  Permite subir archivos de dos maneras:
  - **Archivo Normal:** Se encripta el contenido del archivo y se sube junto con la clave pública.
  - **Archivo Firmado:** Similar a la subida normal, pero además incluye la firma digital utilizando la clave privada del usuario.

- **Descarga de Archivos:**  
  Seleccionando un archivo de la lista, se descarga y se desencripta localmente utilizando la clave privada del usuario.

- **Verificación de Archivos:**  
  Permite al usuario verificar la integridad del archivo comparando el hash calculado y, en caso de estar firmado, verifica la firma digital.

### Backend

El módulo **Backend.py** implementa una API REST que ofrece los siguientes endpoints:

- **POST /register:**  
  Registra un usuario nuevo. Almacena el usuario y la contraseña hasheada en la base de datos interna.  
  *Parámetros:* `username`, `password`.

- **POST /login:**  
  Valida las credenciales de un usuario y emite un token de acceso (JWT).  
  *Parámetros:* `username`, `password`.

- **GET /archivos:**  
  Lista todos los archivos guardados, mostrando el nombre, el hash y si se ha firmado digitalmente.

- **POST /guardar:**  
  Guarda un archivo. Se requiere que el archivo se envíe en formato Base64 y encriptado.  
  *Parámetros obligatorios:* `file_name`, `file_data`, `file_pub_key`.  
  *Parámetro opcional:* `sign_priv_key` para firmar el archivo.

- **GET /archivos/{filename}/descargar:**  
  Permite descargar un archivo encriptado. El servidor devuelve el archivo encriptado, la clave pública utilizada y el nombre del archivo original.

- **POST /verificar:**  
  Verifica la integridad y autenticidad de un archivo mediante el cálculo de su hash y la verificación de la firma digital.  
  *Parámetros:* `file_name`, `file_data`, `sign_pub_key`.

El backend utiliza JWT para autenticar las solicitudes. Las credenciales se envían en la cabecera (`Authorization: Bearer <token>`).

---

## Encriptación y Firma Digital

### Encriptación (Encrypt.py)

- **Generación de claves RSA:**  
  La función `generate_rsa_keys()` crea un par de claves (pública y privada) de 2048 bits.
  
- **Encriptación de datos:**  
  La función `encrypt(plaintext, public_key_str)` divide el contenido a encriptar en bloques (chunks) de tamaño definido por `CHUNK_SIZE` y encripta cada bloque individualmente utilizando la clave pública. Los bloques encriptados se codifican en Base64 y se serializan en formato JSON.

- **Desencriptación de datos:**  
  La función `decrypt(encrypted_payload, private_key_str)` realiza la operación inversa: descodifica el JSON obtenido, desencripta cada bloque utilizando la clave privada y reconstruye el contenido original.


### Firma Digital (Sign.py)

- **Firma de archivos:**  
  La función `sign(file_bytes, private_key_str)` firma el contenido del archivo utilizando la clave privada del usuario. Se utiliza el esquema de padding PSS con SHA256 para la seguridad.

- **Verificación de firma:**  
  La función `verify_signature(file_bytes, signature_b64, public_key_str)` verifica la firma utilizando la clave pública correspondiente. Devuelve `True` si la firma es válida y `False` en caso contrario.

Ambas funcionalidades de firma digital aseguran que cualquier alteración del archivo se detecte durante la verificación.

---

## Notas de Seguridad

- **Gestión de Claves:**  
  Las claves RSA se generan en el momento del registro y se almacenan localmente en el directorio `./Keys`. Se recomienda proteger estos ficheros, ya que son críticos para la seguridad de la aplicación.

- **Encriptación sin Padding:**  
  La implementación actual de RSA en el módulo de encriptación no utiliza un esquema de padding, lo que la hace vulnerable a ciertos ataques. Para entornos de producción, se recomienda utilizar RSA con OAEP o esquemas de cifrado simétrico más robustos.

- **Almacenamiento de Datos:**  
  La base de datos interna se almacena utilizando pickle en un archivo binario (`DB.bin`), lo cual es adecuado únicamente para prototipos o pruebas de concepto. En un entorno real se debe utilizar una base de datos segura y escalable.

---
