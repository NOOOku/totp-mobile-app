from passlib.context import CryptContext
from datetime import datetime, timedelta
from typing import Union
from jose import JWTError, jwt
import pyotp
import secrets
import os

# Конфигурация для JWT
SECRET_KEY = os.getenv("SECRET_KEY", secrets.token_hex(32))  # Генерируем безопасный ключ
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Union[timedelta, None] = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def generate_totp_secret() -> tuple[str, str]:
    """Генерирует случайный секрет для TOTP и его короткую версию.
    
    Returns:
        tuple[str, str]: (полный_секрет, короткий_секрет)
    """
    full_secret = pyotp.random_base32()
    short_secret = full_secret[:6]  # Берем первые 6 символов как короткий ключ
    return full_secret, short_secret

def verify_totp(secret: str, token: str) -> bool:
    """Проверяет TOTP токен."""
    totp = pyotp.TOTP(secret)
    return totp.verify(token) 