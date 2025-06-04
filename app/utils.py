from passlib.context import CryptContext
import datetime
from typing import Union
from jose import JWTError, jwt
import pyotp
import secrets
import os
import logging

# JWT configuration
SECRET_KEY = os.getenv("SECRET_KEY", secrets.token_hex(32))
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Union[datetime.timedelta, None] = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.datetime.utcnow() + expires_delta
    else:
        expire = datetime.datetime.utcnow() + datetime.timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def generate_short_secret() -> str:
    """Generate a short secret key using easily distinguishable characters."""
    ALLOWED_CHARS = "23456789ABCDEFGHJKMNPQRSTUVWXYZ"
    length = 6
    return ''.join(secrets.choice(ALLOWED_CHARS) for _ in range(length))

def generate_totp_secret() -> tuple[str, str]:
    """Generate a random TOTP secret and its short version.
    
    Returns:
        tuple[str, str]: (full_secret, short_secret)
    """
    logger = logging.getLogger(__name__)
    try:
        full_secret = pyotp.random_base32()
        short_secret = generate_short_secret()
        logger.info(f"Generated new TOTP secret. Short key: {short_secret}, Full key: {full_secret}")
        return full_secret, short_secret
    except Exception as e:
        logger.error(f"Error generating TOTP secret: {str(e)}")
        raise

def verify_totp(secret: str, token: str) -> bool:
    """Verify a TOTP token."""
    logger = logging.getLogger(__name__)
    try:
        logger.info(f"Verifying TOTP token. Secret: {secret}, Token: {token}")
        
        # Проверяем формат секрета и токена
        if not secret or not token:
            logger.error("Secret or token is empty")
            return False
            
        if not token.isdigit() or len(token) != 6:
            logger.error(f"Invalid token format. Token: {token}")
            return False

        # Нормализуем секрет (убираем пробелы и переводим в верхний регистр)
        normalized_secret = secret.strip().upper()
        logger.info(f"Normalized secret: {normalized_secret}")

        # Создаем TOTP объект с параметрами expo-totp
        totp = pyotp.TOTP(
            normalized_secret,
            digits=6,        # expo-totp default
            interval=30,     # expo-totp default
            digest='sha1'    # expo-totp default
        )
        
        # Получаем текущее время
        current_time = datetime.datetime.now()
        logger.info(f"Current time: {current_time.timestamp()}")
        
        # Получаем текущий код для сравнения
        current_code = totp.now()
        logger.info(f"Current TOTP code: {current_code}, Provided token: {token}")
        
        # Получаем коды для соседних интервалов для отладки
        prev_code = totp.at(current_time - datetime.timedelta(seconds=30))
        next_code = totp.at(current_time + datetime.timedelta(seconds=30))
        logger.info(f"Previous code: {prev_code}, Next code: {next_code}")
        
        # Проверяем код с окном в 1 интервал (30 секунд до и после)
        is_valid = totp.verify(token, valid_window=1)
        logger.info(f"TOTP verification result: {is_valid}")
        
        return is_valid
    except Exception as e:
        logger.error(f"Error verifying TOTP: {str(e)}")
        return False 