from passlib.context import CryptContext
import datetime
from typing import Union
from jose import JWTError, jwt
from pyotp import TOTP
import secrets
import os
import logging
import re
import time

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

def generate_base32_secret(length: int = 32) -> str:
    """Generate a random base32 secret of specified length."""
    ALLOWED_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"  # Base32 alphabet
    return ''.join(secrets.choice(ALLOWED_CHARS) for _ in range(length))

def generate_totp_secret() -> tuple[str, str]:
    """Generate a random TOTP secret and its short version.
    
    Returns:
        tuple[str, str]: (full_secret, short_secret)
    """
    logger = logging.getLogger(__name__)
    try:
        # Generate a random base32 secret
        full_secret = generate_base32_secret(32)
        
        # Generate short key
        short_secret = generate_short_secret()
        
        # Create TOTP object with proper parameters
        totp = TOTP(
            full_secret,
            digits=6,
            interval=30,
            digest='sha1'
        )
        
        # Create URI for QR code (for Google Authenticator compatibility)
        totp_uri = totp.provisioning_uri(
            name="TOTP App",
            issuer_name="Your App"
        )
        
        logger.info(f"Generated new TOTP secret. Short key: {short_secret}")
        logger.info(f"Full key: {full_secret}")
        logger.info(f"TOTP URI: {totp_uri}")
        
        return full_secret, short_secret
    except Exception as e:
        logger.error(f"Error generating TOTP secret: {str(e)}")
        raise

def normalize_base32_secret(secret: str) -> str:
    """
    Нормализует и валидирует base32 секрет: только A-Z и 2-7, без пробелов, в верхнем регистре.
    Идентична клиентской реализации.
    """
    normalized = re.sub(r'\s+', '', secret.strip().upper())
    if not re.match(r'^[A-Z2-7]+$', normalized):
        raise ValueError('Secret is not valid base32 (A-Z, 2-7 only)')
    return normalized

def verify_totp(secret: str, token: str, timestamp: int = None) -> bool:
    """Verify a TOTP token.
    
    Args:
        secret: The TOTP secret key
        token: The TOTP token to verify
        timestamp: Optional timestamp to use for verification (for handling time drift)
    """
    logger = logging.getLogger(__name__)
    try:
        logger.info("=== TOTP Verification Debug Info ===")
        logger.info(f"Input secret: {secret}")
        logger.info(f"Input token: {token}")
        logger.info(f"Input timestamp: {timestamp}")
        
        # Проверяем формат секрета и токена
        if not secret or not token:
            logger.error("Secret or token is empty")
            return False
            
        if not token.isdigit() or len(token) != 6:
            logger.error(f"Invalid token format. Token: {token}")
            return False

        # Строго нормализуем и валидируем секрет
        try:
            normalized_secret = normalize_base32_secret(secret)
            logger.info(f"Normalized secret: {normalized_secret}")
            logger.info(f"Secret length: {len(normalized_secret)}")
        except Exception as e:
            logger.error(f"Invalid base32 secret: {e}")
            return False

        # Логируем конфигурацию TOTP
        logger.info("TOTP Configuration:")
        logger.info("- Digits: 6")
        logger.info("- Interval: 30")
        logger.info("- Algorithm: sha1")

        # Создаем TOTP объект с теми же параметрами, что и при генерации
        totp = TOTP(
            normalized_secret,
            digits=6,
            interval=30,
            digest='sha1'
        )
        
        # Получаем текущее время в секундах
        current_timestamp = timestamp if timestamp is not None else int(time.time())
        logger.info(f"Using current time: {current_timestamp}")
        
        # Конвертируем в UTC для логирования
        current_time = datetime.datetime.fromtimestamp(current_timestamp, tz=datetime.timezone.utc)
        logger.info(f"Converted to UTC: {current_time.isoformat()}")
        
        # Вычисляем T0 (количество 30-секундных интервалов)
        time_counter = int(current_timestamp / 30)
        logger.info(f"Time counter (T0): {time_counter}")
        
        # Генерируем текущий код
        current_code = totp.at(current_timestamp)
        logger.info(f"Generated TOTP code: {current_code}")
        logger.info(f"Provided token: {token}")
        
        # Генерируем коды для соседних интервалов
        prev_time = current_timestamp - 30
        next_time = current_timestamp + 30
        prev_code = totp.at(prev_time)
        next_code = totp.at(next_time)
        logger.info(f"Previous interval code: {prev_code}")
        logger.info(f"Next interval code: {next_code}")
        
        # Проверяем код с расширенным окном
        is_valid = totp.verify(token, valid_window=2)
        logger.info(f"Verification result: {is_valid}")
        logger.info("=== End Debug Info ===")
        
        return is_valid
        
    except Exception as e:
        logger.error(f"Error verifying TOTP: {str(e)}")
        return False 