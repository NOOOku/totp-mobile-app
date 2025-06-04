from passlib.context import CryptContext
from datetime import datetime, timedelta
from typing import Union
from jose import JWTError, jwt
import pyotp
import secrets
import os
import logging

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

def generate_short_secret() -> str:
    """Генерирует короткий секретный ключ.
    Использует только буквы и цифры, которые легко различить.
    Исключает похожие символы (0/O, 1/I/L, etc.)
    """
    # Используем только хорошо различимые символы
    ALLOWED_CHARS = "23456789ABCDEFGHJKMNPQRSTUVWXYZ"
    length = 6
    return ''.join(secrets.choice(ALLOWED_CHARS) for _ in range(length))

def generate_totp_secret() -> tuple[str, str]:
    """Генерирует случайный секрет для TOTP и его короткую версию.
    
    Returns:
        tuple[str, str]: (полный_секрет, короткий_секрет)
    """
    logger = logging.getLogger(__name__)
    
    try:
    full_secret = pyotp.random_base32()
        # Генерируем отдельный короткий ключ
        short_secret = generate_short_secret()
        logger.info(f"Сгенерирован новый TOTP секрет. Короткий ключ: {short_secret}, Полный ключ: {full_secret}")
    return full_secret, short_secret
    except Exception as e:
        logger.error(f"Ошибка при генерации TOTP секрета: {str(e)}")
        raise

def verify_totp(secret: str, token: str) -> bool:
    """Проверяет TOTP токен."""
    totp = pyotp.TOTP(secret)
    return totp.verify(token) 