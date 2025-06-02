from sqlalchemy import create_engine, event, text
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

logger.info(f"Initial DATABASE_URL: {DATABASE_URL}")

def get_database_url():
    logger.info("Configuring database URL...")
    db_url = DATABASE_URL

    # Замена postgres:// на postgresql:// если необходимо
    if db_url.startswith("postgres://"):
        db_url = db_url.replace("postgres://", "postgresql://")
        logger.info("Replaced postgres:// with postgresql:// in database URL")

    # Добавляем параметры SSL для production
    if "localhost" not in db_url:
        parsed_url = urllib.parse.urlparse(db_url)
        query_dict = dict(urllib.parse.parse_qsl(parsed_url.query))
        
        # Добавляем параметры SSL
        query_dict.update({
            "sslmode": "require"
        })
        
        # Собираем URL обратно
        query_string = urllib.parse.urlencode(query_dict)
        db_url = urllib.parse.urlunparse(
            (
                parsed_url.scheme,
                parsed_url.netloc,
                parsed_url.path,
                parsed_url.params,
                query_string,
                parsed_url.fragment
            )
        )
        logger.info("Added SSL parameters to database URL")

    logger.info(f"Final database URL configuration: {db_url}")
    return db_url

def create_db_engine(retries=5, delay=5):
    for attempt in range(retries):
        try:
            logger.info(f"Attempting to create database engine (attempt {attempt + 1}/{retries})")
            db_url = get_database_url()
            
            engine = create_engine(
                db_url,
                pool_pre_ping=True,
                pool_size=5,
                max_overflow=10,
                connect_args={
                    "connect_timeout": 60,
                }
            )
            
            # Проверяем подключение с использованием text()
            with engine.connect() as connection:
                connection.execute(text("SELECT 1"))
                connection.commit()
            logger.info("Database engine created and connected successfully")
            return engine
        except Exception as e:
            logger.error(f"Failed to create database engine (attempt {attempt + 1}): {str(e)}")
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