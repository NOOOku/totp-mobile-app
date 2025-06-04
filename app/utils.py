from passlib.context import CryptContext
import datetime
from typing import Union
from jose import JWTError, jwt
import secrets
import os
import logging
import re
import time
import base64
import hmac
import hashlib
import struct

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
        
        logger.info(f"Generated new TOTP secret. Short key: {short_secret}")
        logger.info(f"Full key: {full_secret}")
        
        return full_secret, short_secret
    except Exception as e:
        logger.error(f"Error generating TOTP secret: {str(e)}")
        raise

def normalize_base32_secret(secret: str) -> str:
    """Normalize and validate base32 secret: A-Z and 2-7 only, no spaces, uppercase."""
    normalized = re.sub(r'\s+', '', secret.strip().upper())
    if not re.match(r'^[A-Z2-7]+$', normalized):
        raise ValueError('Secret is not valid base32 (A-Z, 2-7 only)')
    return normalized

def base32_decode(encoded: str) -> bytes:
    """Decode base32 string to bytes."""
    # Add padding if necessary
    padding = len(encoded) % 8
    if padding != 0:
        encoded += '=' * (8 - padding)
    return base64.b32decode(encoded.upper())

def generate_totp(secret: str, timestamp: int = None) -> str:
    """Generate TOTP code for given secret and timestamp."""
    if timestamp is None:
        timestamp = int(time.time())
    
    # Counter is number of 30-second intervals since Unix epoch
    counter = struct.pack('>Q', timestamp // 30)
    
    # Decode base32 secret
    key = base32_decode(secret)
    
    # Calculate HMAC-SHA1
    hmac_obj = hmac.new(key, counter, hashlib.sha1)
    hmac_result = hmac_obj.digest()
    
    # Get offset
    offset = hmac_result[-1] & 0xf
    
    # Generate 4-byte code
    code_bytes = hmac_result[offset:offset + 4]
    code_num = struct.unpack('>I', code_bytes)[0]
    
    # Get 6 digits
    code = code_num & 0x7fffffff
    code = str(code % 1000000)
    
    # Pad with zeros if necessary
    return code.zfill(6)

def verify_totp(secret: str, token: str, timestamp: int = None) -> bool:
    """Verify a TOTP token.
    
    Args:
        secret: The TOTP secret key
        token: The TOTP token to verify
        timestamp: Optional timestamp to use for verification
    """
    logger = logging.getLogger(__name__)
    try:
        logger.info("=== TOTP Verification Debug Info ===")
        logger.info(f"Input secret: {secret}")
        logger.info(f"Input token: {token}")
        logger.info(f"Input timestamp: {timestamp}")
        
        # Check secret and token format
        if not secret or not token:
            logger.error("Secret or token is empty")
            return False
            
        if not token.isdigit() or len(token) != 6:
            logger.error(f"Invalid token format. Token: {token}")
            return False

        # Normalize and validate secret
        try:
            normalized_secret = normalize_base32_secret(secret)
            logger.info(f"Normalized secret: {normalized_secret}")
            logger.info(f"Secret length: {len(normalized_secret)}")
        except Exception as e:
            logger.error(f"Invalid base32 secret: {e}")
            return False

        # Get current timestamp
        current_timestamp = timestamp if timestamp is not None else int(time.time())
        logger.info(f"Using current time: {current_timestamp}")
        
        # Check codes for current and adjacent intervals
        for drift in [-1, 0, 1]:  # Check previous, current, and next interval
            check_time = current_timestamp + (drift * 30)
            generated_token = generate_totp(normalized_secret, check_time)
            logger.info(f"Generated token for drift {drift}: {generated_token}")
            
            if token == generated_token:
                logger.info(f"Token matched with drift {drift}")
                return True
        
        logger.info("No matching tokens found")
        return False
        
    except Exception as e:
        logger.error(f"Error verifying TOTP: {str(e)}")
        return False 