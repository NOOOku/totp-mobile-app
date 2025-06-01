from sqlalchemy import create_engine, event
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.engine import Engine
import os
import urllib.parse
import logging
import time

logger = logging.getLogger(__name__)

# Получаем URL базы данных из переменной окружения
DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    raise ValueError("DATABASE_URL environment variable is not set")

# Обработка URL базы данных для поддержки SSL
def get_database_url():
    logger.info("Configuring database URL...")
    
    # Замена postgres:// на postgresql:// если необходимо
    if DATABASE_URL.startswith("postgres://"):
        db_url = DATABASE_URL.replace("postgres://", "postgresql://")
    else:
        db_url = DATABASE_URL
    
    # Добавляем SSL параметры
    parsed_url = urllib.parse.urlparse(db_url)
    query_params = urllib.parse.parse_qs(parsed_url.query) if parsed_url.query else {}
    
    # Добавляем параметры SSL для production
    query_params.update({
        "sslmode": ["require"],
    })
    
    new_query = urllib.parse.urlencode(query_params, doseq=True)
    db_url = urllib.parse.urlunparse(
        parsed_url._replace(query=new_query)
    )
    
    logger.info("Database URL configured successfully")
    return db_url

def create_db_engine(retries=5, delay=5):
    for attempt in range(retries):
        try:
            logger.info(f"Attempting to create database engine (attempt {attempt + 1}/{retries})")
            db_url = get_database_url()
            logger.info(f"Using database URL: {db_url.split('@')[0]}@[HIDDEN]")
            
            engine = create_engine(
                db_url,
                pool_pre_ping=True,
                pool_size=5,
                max_overflow=10,
                connect_args={
                    "connect_timeout": 60,
                }
            )
            
            # Проверяем подключение
            with engine.connect() as connection:
                connection.execute("SELECT 1")
            logger.info("Database engine created successfully")
            return engine
        except Exception as e:
            logger.error(f"Failed to create database engine: {str(e)}")
            if attempt < retries - 1:
                logger.info(f"Retrying in {delay} seconds...")
                time.sleep(delay)
            else:
                logger.error("Max retries reached, raising exception")
                raise

engine = create_db_engine()

@event.listens_for(Engine, "connect")
def connect(dbapi_connection, connection_record):
    logger.info("New database connection established")

@event.listens_for(Engine, "disconnect")
def disconnect(dbapi_connection, connection_record):
    logger.info("Database connection closed")

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

Base = declarative_base()

# Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close() 