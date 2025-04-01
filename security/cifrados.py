# -------------------------------------------------- Cifrado SHA-256 -------------------------------------------------------------
import hashlib 

def password_sha256(password: str) -> str:
    """
    Función que recibe una contraseña y devuelve su hash en formato SHA-256.
    """
    return hashlib.sha256(password.encode()).hexdigest()
