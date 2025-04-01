import hashlib 
import jwt 
import datetime
import os
from dotenv import load_dotenv

load_dotenv()
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"

def password_sha256(password: str) -> str:
    """
    Función que recibe una contraseña y devuelve su hash en formato SHA-256.
    """
    return hashlib.sha256(password.encode()).hexdigest()

def password_verify(password: str, hashed_password: str) -> bool:
    """
    Función que verifica si una contraseña coincide con su hash.
    """
    return password_sha256(password) == hashed_password

def create_jwt_token(user_id: str) -> str:
    """
    Función que genera un JWT con el ID del usuario y una expiración de 1 hora.
    """
    payload = {
        "user_id": user_id,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    return token

def verify_jwt_token(token: str) -> dict:
    """
    Función que verifica un JWT y devuelve su contenido si es válido.
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        return {"error": "Token has expired"}
    except jwt.InvalidTokenError:
        return {"error": "Invalid token"}
