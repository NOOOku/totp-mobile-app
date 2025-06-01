from sqlalchemy.orm import Session
from . import models, schemas, utils
import logging
from sqlalchemy.exc import SQLAlchemyError

# Настройка логирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def get_user(db: Session, user_id: int):
    try:
        return db.query(models.User).filter(models.User.id == user_id).first()
    except SQLAlchemyError as e:
        logger.error(f"Database error in get_user: {str(e)}")
        raise

def get_user_by_email(db: Session, email: str):
    try:
        return db.query(models.User).filter(models.User.email == email).first()
    except SQLAlchemyError as e:
        logger.error(f"Database error in get_user_by_email: {str(e)}")
        raise

def get_user_by_username(db: Session, username: str):
    try:
        return db.query(models.User).filter(models.User.username == username).first()
    except SQLAlchemyError as e:
        logger.error(f"Database error in get_user_by_username: {str(e)}")
        raise

def create_user(db: Session, user: schemas.UserCreate):
    try:
        logger.info(f"Creating new user with username: {user.username}")
        hashed_password = utils.get_password_hash(user.password)
        db_user = models.User(
            username=user.username,
            email=user.email,
            hashed_password=hashed_password,
            is_active=True
        )
        db.add(db_user)
        db.commit()
        db.refresh(db_user)
        logger.info(f"User created successfully: {user.username}")
        return db_user
    except SQLAlchemyError as e:
        logger.error(f"Database error in create_user: {str(e)}")
        db.rollback()
        raise
    except Exception as e:
        logger.error(f"Unexpected error in create_user: {str(e)}")
        db.rollback()
        raise

def create_user_totp(db: Session, user_id: int) -> models.TOTPSecret:
    """Создает TOTP секрет для пользователя."""
    full_secret, short_secret = utils.generate_totp_secret()
    db_totp = models.TOTPSecret(
        user_id=user_id,
        secret=full_secret,
        short_secret=short_secret,
        is_verified=False
    )
    db.add(db_totp)
    db.commit()
    db.refresh(db_totp)
    return db_totp

def get_totp_by_short_secret(db: Session, short_secret: str) -> models.TOTPSecret:
    """Получает TOTP секрет по короткому ключу."""
    return db.query(models.TOTPSecret).filter(models.TOTPSecret.short_secret == short_secret).first()

def verify_user_totp(db: Session, user_id: int):
    try:
        logger.info(f"Verifying TOTP for user_id: {user_id}")
        db_totp = db.query(models.TOTPSecret).filter(models.TOTPSecret.user_id == user_id).first()
        if db_totp:
            db_totp.is_verified = True
            db.commit()
            db.refresh(db_totp)
            logger.info(f"TOTP verified successfully for user_id: {user_id}")
        return db_totp
    except SQLAlchemyError as e:
        logger.error(f"Database error in verify_user_totp: {str(e)}")
        db.rollback()
        raise

def authenticate_user(db: Session, username: str, password: str):
    try:
        logger.info(f"Attempting to authenticate user: {username}")
        user = get_user_by_username(db, username)
        if not user:
            logger.info(f"User not found: {username}")
            return False
        logger.info(f"User found: {username}, verifying password")
        if not utils.verify_password(password, user.hashed_password):
            logger.info(f"Password verification failed for user: {username}")
            return False
        logger.info(f"Authentication successful for user: {username}")
        return user
    except SQLAlchemyError as e:
        logger.error(f"Database error in authenticate_user: {str(e)}")
        raise 