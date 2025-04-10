# API de Gestión de Archivos con Firmas Digitales
Este proyecto es una API desarrollada con FastAPI que permite a los usuarios subir archivos, cifrarlos con RSA/ECC, firmarlos, almacenar los metadatos en MongoDB Atlas y posteriormente descargarlos con sus respectivas llaves públicas.

## 🚀 Requisitos
- Python 3.10+
- MongoDB Atlas

## 📁 Clonar el repositorio
```bash
git clone https://github.com/Sebas021210/Lab4-CifradosAsimetricos-API
```

## 📦 Instalación de dependencias
```bash
pip install fastapi uvicorn python-dotenv pymongo==3.11 'pymongo[srv]' pyjwt python-multipart
```

## ⚙️ Variables de entorno
Crea un archivo .env o define variables directamente en el código. Asegúrate de tener:
```
SECRET_KEY=tu_clave_secreta
```

## ▶️ Ejecutar el servidor
```bash
uvicorn main:app --reload
```

## 🔐 Notas de seguridad
JWT debe incluirse en los headers como:
- Authorization: Bearer <token>
- Las claves públicas (RSA y ECC) se generan y almacenan por usuario.
- El sistema comprime los archivos y sus llaves en un .zip para descarga.

## 📂 Estructura del proyecto
```bash
.
├── main.py
├── routers/
│   ├── route.py
├── models/
│   ├── model.py
├── config/
│   ├── database.py
├── security/
│   ├── cifrados.py
├── .env
└── README.md
```

![Diagrama](./assets/DiagramaLab4-Cifrados.png)
