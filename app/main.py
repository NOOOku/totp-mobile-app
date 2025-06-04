from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from datetime import timedelta
from . import crud, models, schemas, utils
from .database import SessionLocal, engine
import logging
from typing import Annotated
from sqlalchemy.exc import SQLAlchemyError
from .routers import auth
import datetime

# Настройка логирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI()

# Добавляем CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "https://totp-mobile-app.onrender.com",
        "http://totp-mobile-app.onrender.com"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Подключаем маршрутизатор аутентификации
app.include_router(auth.router, prefix="/auth", tags=["auth"])

# Получение соединения с базой данных
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.get("/")
def root():
    return {"status": "ok"}

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/token")  # Обновляем путь к токену

@app.post("/auth/register", response_model=schemas.User)
async def register_user(user: schemas.UserCreate, db: Session = Depends(get_db)):
    logger.info(f"Registration attempt for user: {user.username}")
    try:
        # Проверяем существование пользователя
        if crud.get_user_by_email(db, email=user.email):
            logger.warning(f"Registration failed: Email already registered - {user.email}")
            raise HTTPException(
                status_code=400,
                detail="Email already registered"
            )
        
        if crud.get_user_by_username(db, username=user.username):
            logger.warning(f"Registration failed: Username already taken - {user.username}")
            raise HTTPException(
                status_code=400,
                detail="Username already taken"
            )
        
        # Создаем пользователя
        try:
            db_user = crud.create_user(db=db, user=user)
            logger.info(f"User created successfully: {user.username}")
        except SQLAlchemyError as e:
            logger.error(f"Database error during user creation: {str(e)}")
            raise HTTPException(
                status_code=500,
                detail=f"Error creating user: {str(e)}"
            )
        
        # Создаем TOTP секрет
        try:
            totp = crud.create_user_totp(db=db, user_id=db_user.id)
            logger.info(f"TOTP secret created for user: {user.username}")
        except SQLAlchemyError as e:
            logger.error(f"Database error during TOTP creation: {str(e)}")
            # Удаляем созданного пользователя, если не удалось создать TOTP
            db.delete(db_user)
            db.commit()
            raise HTTPException(
                status_code=500,
                detail=f"Error creating TOTP secret: {str(e)}"
            )
        
        return {
            "id": db_user.id,
            "username": db_user.username,
            "email": db_user.email,
            "is_active": db_user.is_active,
            "totp_secret": {
                "id": totp.id,
                "secret": totp.secret,
                "short_secret": totp.short_secret,
                "is_verified": totp.is_verified,
                "user_id": totp.user_id
            }
        }
    except HTTPException as he:
        raise he
    except Exception as e:
        logger.error(f"Unexpected error during registration: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=str(e)
        )

@app.post("/auth/verify-totp")
async def verify_totp(
    totp_code: str,
    db: Session = Depends(get_db),
    token: str = Depends(oauth2_scheme)
):
    try:
        payload = utils.jwt.decode(token, utils.SECRET_KEY, algorithms=[utils.ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
            )
    except utils.JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
        )
    
    user = crud.get_user_by_username(db, username=username)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )
    
    if not user.totp_secret:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="TOTP not set up for this user",
        )
    
    if utils.verify_totp(user.totp_secret.secret, totp_code):
        # Если код верный и секрет еще не верифицирован, верифицируем его
        if not user.totp_secret.is_verified:
            crud.verify_user_totp(db, user.id)
            logger.info(f"TOTP secret verified for user {user.username}")
        return {"message": "TOTP verified successfully"}
    
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid TOTP code",
    )

@app.get("/server-time")
async def get_server_time():
    """
    Возвращает текущее время сервера в формате Unix timestamp
    """
    current_time = datetime.datetime.now().timestamp()
    return {"server_time": current_time} 