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

# Настройка логирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI()


@app.get("/")
def root():
    return {"status": "ok"}


# Настройка CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # В продакшене замените на конкретные домены
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Обработка ошибок
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Global error: {str(exc)}")
    return JSONResponse(
        status_code=500,
        content={"detail": str(exc)}
    )

@app.middleware("http")
async def db_session_middleware(request: Request, call_next):
    response = await call_next(request)
    if request.headers.get("origin") in ["http://localhost:3000", "http://127.0.0.1:3000"]:
        response.headers["Access-Control-Allow-Origin"] = request.headers["origin"]
        response.headers["Access-Control-Allow-Credentials"] = "true"
    return response

# Проверка работоспособности API
@app.get("/health")
async def health_check():
    return {"status": "ok"}

# Создаем таблицы при запуске
models.Base.metadata.create_all(bind=engine)

# Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

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

@app.post("/auth/token", response_model=schemas.Token)
async def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    logger.info(f"Login attempt for user: {form_data.username}")
    logger.info(f"Received form data: username={form_data.username}, password_length={len(form_data.password)}")
    logger.info(f"TOTP code present: {'totp_code' in form_data.__dict__}")
    
    user = crud.authenticate_user(db, form_data.username, form_data.password)
    if not user:
        logger.info(f"Authentication failed for user: {form_data.username}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    logger.info(f"User authenticated successfully: {form_data.username}")
    # Проверяем TOTP код, если пользователь уже настроил 2FA
    if user.totp_secret and user.totp_secret.is_verified:
        logger.info(f"TOTP verification required for user: {form_data.username}")
        totp_code = getattr(form_data, 'totp_code', None)
        if not totp_code:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="TOTP code required",
                headers={"WWW-Authenticate": "Bearer"},
            )
        if not utils.verify_totp(user.totp_secret.secret, totp_code):
            logger.info(f"TOTP verification failed for user: {form_data.username}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid TOTP code",
                headers={"WWW-Authenticate": "Bearer"},
            )
        logger.info(f"TOTP verified successfully for user: {form_data.username}")

    access_token_expires = timedelta(minutes=utils.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = utils.create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    logger.info(f"Access token generated for user: {form_data.username}")
    return {"access_token": access_token, "token_type": "bearer"}

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
        crud.verify_user_totp(db, user.id)
        return {"message": "TOTP verified successfully"}
    
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid TOTP code",
    ) 