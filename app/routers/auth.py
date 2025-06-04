from fastapi import APIRouter, Depends, HTTPException, status, Header
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from .. import crud, models, schemas, utils
from ..database import get_db
from pydantic import BaseModel
import logging
from typing import Optional, Dict
import jwt
from datetime import timedelta

logger = logging.getLogger(__name__)

router = APIRouter()

class Token(BaseModel):
    access_token: str
    token_type: str
    user: schemas.User
    full_secret: str
    user_id: int

class MobileLoginRequest(BaseModel):
    short_secret: str

@router.post("/token", response_model=Token)
async def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    """
    Вход по логину и паролю, возвращает JWT токен и TOTP секрет
    """
    logger.info(f"Попытка входа для пользователя: {form_data.username}")
    user = crud.authenticate_user(db, form_data.username, form_data.password)
    if not user:
        logger.error(f"Неверные учетные данные для пользователя: {form_data.username}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token_expires = timedelta(minutes=utils.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = utils.create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    
    # Получаем TOTP секрет пользователя
    totp_secret = crud.get_totp_by_user_id(db, user.id)
    if not totp_secret:
        logger.error(f"TOTP секрет не найден для пользователя: {user.id}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="TOTP secret not found"
        )
    
    logger.info(f"Успешный вход для пользователя: {user.username}")
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": user,
        "full_secret": totp_secret.secret,
        "user_id": user.id
    }

@router.post("/mobile/login")
async def mobile_login(
    request: MobileLoginRequest,
    db: Session = Depends(get_db),
    authorization: Optional[str] = Header(None)
):
    """
    Вход в мобильное приложение по короткому ключу.
    Возвращает полный секрет для генерации TOTP.
    """
    logger.info("Получен запрос на мобильный вход")
    logger.info(f"Тело запроса: {request}")
    logger.info(f"Заголовок Authorization: {authorization}")
    
    if not authorization or not authorization.startswith("Bearer "):
        logger.error("Отсутствует или неверный формат токена авторизации")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid authorization token"
        )
    
    try:
        # Декодируем токен
        token = authorization.replace("Bearer ", "")
        logger.info(f"Декодируем токен: {token}")
        payload = jwt.decode(token, utils.SECRET_KEY, algorithms=[utils.ALGORITHM])
        username = payload.get("sub")
        logger.info(f"Декодирован токен для пользователя: {username}")
        
        # Получаем пользователя
        user = crud.get_user_by_username(db, username)
        if not user:
            logger.error(f"Пользователь не найден: {username}")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        logger.info(f"Найден пользователь с ID: {user.id}")
        
        # Нормализуем короткий ключ
        normalized_secret = request.short_secret.strip().upper()
        logger.info(f"Нормализованный короткий ключ: {normalized_secret}")
        
        # Получаем TOTP секрет пользователя
        totp_secret = crud.get_totp_by_user_id(db, user.id)
        if not totp_secret:
            logger.error(f"Не найден TOTP секрет для пользователя: {user.id}")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="TOTP secret not found"
            )
        
        # Проверяем короткий ключ
        if totp_secret.short_secret != normalized_secret:
            logger.error(f"Неверный короткий ключ для пользователя {user.id}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid short secret"
            )
        
        logger.info(f"Успешная аутентификация для пользователя {user.id}")
        return {
            "full_secret": totp_secret.secret,
            "user_id": user.id
        }
    except jwt.JWTError as e:
        logger.error(f"Ошибка при декодировании JWT: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials"
        )
    except Exception as e:
        logger.error(f"Ошибка при обработке запроса: {str(e)}")
        raise

@router.post("/verify-credentials")
async def verify_credentials(
    credentials: Dict[str, str],
    db: Session = Depends(get_db)
):
    """
    Первый шаг аутентификации - проверка учетных данных
    """
    username = credentials.get("username")
    password = credentials.get("password")
    
    if not username or not password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username and password are required"
        )

    user = crud.authenticate_user(db, username, password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Неверное имя пользователя или пароль"
        )

    # Если пользователь найден, возвращаем успешный результат
    return {"valid": True, "requires_totp": bool(user.totp_secret and user.totp_secret.is_verified)}

@router.post("/login")
async def login(
    login_data: Dict[str, str],
    db: Session = Depends(get_db)
):
    """
    Второй шаг аутентификации - проверка TOTP и выдача токена
    """
    username = login_data.get("username")
    password = login_data.get("password")
    totp_code = login_data.get("totp_code")

    if not all([username, password, totp_code]):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username, password and TOTP code are required"
        )

    # Повторная проверка учетных данных
    user = crud.authenticate_user(db, username, password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Неверное имя пользователя или пароль"
        )

    # Проверка TOTP кода
    if not user.totp_secret or not user.totp_secret.is_verified:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="TOTP не настроен для этого пользователя"
        )

    if not utils.verify_totp(user.totp_secret.secret, totp_code):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Неверный код аутентификации"
        )

    # Генерация токена доступа
    access_token_expires = timedelta(minutes=utils.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = utils.create_access_token(
        data={"sub": user.username},
        expires_delta=access_token_expires
    )

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "is_active": user.is_active
        }
    } 