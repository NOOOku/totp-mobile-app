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
    """Verify a TOTP token using expo-totp through Node.js."""
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

        # Используем Node.js для проверки через expo-totp
        import subprocess
        import json
        
        # Создаем временный файл с данными
        data = {
            "secret": secret.strip().upper(),
            "token": token
        }
        
        # Запускаем Node.js скрипт
        node_process = subprocess.Popen(
            ["node", "-e", f"""
            const {{ verifyTOTP }} = require('./app/totp_node.js');
            const data = {json.dumps(data)};
            
            verifyTOTP(data.secret, data.token)
                .then(result => console.log(JSON.stringify({{ isValid: result }})))
                .catch(error => console.log(JSON.stringify({{ error: error.message }})));
            """],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        
        # Получаем результат
        stdout, stderr = node_process.communicate()
        
        if stderr:
            logger.error(f"Node.js error: {stderr.decode()}")
            return False
            
        try:
            result = json.loads(stdout.decode())
            is_valid = result.get('isValid', False)
            logger.info(f"TOTP verification result: {is_valid}")
            return is_valid
        except json.JSONDecodeError:
            logger.error(f"Failed to parse Node.js output: {stdout.decode()}")
            return False
            
    except Exception as e:
        logger.error(f"Error verifying TOTP: {str(e)}")
        return False 