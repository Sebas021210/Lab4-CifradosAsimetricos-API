from pydantic import BaseModel
from typing import Optional, List

class User(BaseModel):
    name: str
    last_name: str
    username: str
    email: str
    password: str
    public_key: Optional[str] = None
    files: Optional[List[str]] = []
    files_hash: Optional[List[str]] = []
    files_firma: Optional[List[str]] = []

class Login(BaseModel):
    email: str
    password: str
