from fastapi import Header, HTTPException
import hashlib 
import jwt 
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
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

def get_current_user(authorization: str = Header(None)):
    """
    Middleware para verificar el JWT en las peticiones protegidas.
    """
    if authorization is None:
        raise HTTPException(status_code=401, detail="Missing token")

    token = authorization.split("Bearer ")[-1]
    payload = verify_jwt_token(token)

    if "error" in payload:
        raise HTTPException(status_code=401, detail=payload["error"])
    
    return payload["user_id"]

def generate_key_pair():
    """
    Función para genera un par de llaves RSA (privada y pública).
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_pem.decode(), public_pem.decode()

def generate_ecc_key_pair():
    """
    Genera un par de llaves ECC (privada y pública) usando la curva SECP256R1.
    """
    private_key = ec.generate_private_key(ec.SECP256R1())

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_pem.decode(), public_pem.decode()

def calculate_hash(file_bytes: bytes) -> str:
    """
    Función que calcula el hash SHA-256 de un archivo dado en bytes.
    """
    return hashlib.sha256(file_bytes).hexdigest()

def sign_rsa(private_key: rsa.RSAPrivateKey, data: bytes) -> bytes:
    """
    Función que firma datos usando una llave privada RSA.
    """
    return private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

def sign_ecc(private_key: ec.EllipticCurvePrivateKey, data: bytes) -> bytes:
    """
    Función que firma datos usando una llave privada ECC.
    """
    return private_key.sign(data, ec.ECDSA(hashes.SHA256()))

def verify_signature_rsa(public_key, data: bytes, signature: bytes) -> bool:
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

def verify_signature_ecc(public_key, data: bytes, signature: bytes) -> bool:
    try:
        public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False
