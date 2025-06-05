from fastapi import APIRouter, Depends, HTTPException, status, Header
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from sqlalchemy.orm import Session
from .. import crud, models, schemas, utils
from ..database import get_db
from pydantic import BaseModel
import logging
from typing import Optional, Dict
from jose import jwt, JWTError
from datetime import timedelta, datetime
import secrets
import json

logger = logging.getLogger(__name__)

router = APIRouter()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Store QR sessions in memory (in production, use Redis or similar)
qr_sessions = {}

class Token(BaseModel):
    access_token: str
    token_type: str
    user: schemas.User
    full_secret: str
    user_id: int

class MobileLoginRequest(BaseModel):
    short_secret: str

class QRSession(BaseModel):
    sessionId: str

class QRLoginRequest(BaseModel):
    session_id: str
    username: str
    totp_code: str
    timestamp: int

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
    except JWTError as e:
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
    if not user.totp_secret:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="TOTP не настроен для этого пользователя"
        )

    if utils.verify_totp(user.totp_secret.secret, totp_code):
        # Если код верный и секрет еще не верифицирован, верифицируем его
        if not user.totp_secret.is_verified:
            crud.verify_user_totp(db, user.id)
            logger.info(f"TOTP secret verified for user {user.username}")

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

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Неверный код аутентификации"
    )

@router.post("/qr-session")
async def create_qr_session():
    """Create a new QR session for login"""
    session_id = secrets.token_urlsafe(32)
    qr_sessions[session_id] = {
        "created_at": datetime.utcnow(),
        "status": "pending",
        "token": None
    }
    return {"sessionId": session_id}

@router.get("/qr-session/{session_id}")
async def check_qr_session(session_id: str):
    """Check the status of a QR login session"""
    if session_id not in qr_sessions:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found"
        )
    
    session = qr_sessions[session_id]
    
    # Clean up expired sessions
    if datetime.utcnow() - session["created_at"] > timedelta(minutes=5):
        del qr_sessions[session_id]
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session expired"
        )
    
    return {
        "status": session["status"],
        "token": session["token"] if session["status"] == "authenticated" else None
    }

@router.post("/qr-login")
async def qr_login(request: QRLoginRequest, db: Session = Depends(get_db)):
    """Handle QR code login from mobile app"""
    if request.session_id not in qr_sessions:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found"
        )
    
    session = qr_sessions[request.session_id]
    
    # Verify timestamp to prevent replay attacks
    request_time = datetime.fromtimestamp(request.timestamp / 1000.0)
    if datetime.utcnow() - request_time > timedelta(minutes=5):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Request expired"
        )
    
    # Get user and their TOTP secret
    user = db.query(models.User).filter(models.User.username == request.username).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
        )
    
    # Get TOTP secret from database
    totp_secret = crud.get_totp_by_user_id(db, user.id)
    if not totp_secret:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="TOTP not set up for this user"
        )
    
    # Verify TOTP code
    try:
        normalized_secret = utils.normalize_base32_secret(totp_secret.secret)
        if not utils.verify_totp(normalized_secret, request.totp_code):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid TOTP code"
            )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    
    # Create access token
    access_token = utils.create_access_token(data={"sub": user.username})
    
    # Update session status
    session["status"] = "authenticated"
    session["token"] = access_token
    
    return {"status": "success"} 