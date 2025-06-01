from sqlalchemy import create_engine, event
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.engine import Engine
import os
import urllib.parse
import logging
import time

logger = logging.getLogger(__name__)

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# Проверка переменных окружения
logger.info("Checking environment variables...")
logger.info(f"RENDER env: {os.getenv('RENDER')}")
logger.info(f"PYTHONPATH env: {os.getenv('PYTHONPATH')}")
logger.info(f"Available environment variables: {', '.join(sorted(os.environ.keys()))}")

# Получаем URL базы данных из переменной окружения
DATABASE_URL = os.getenv("DATABASE_URL")

logger.info("Checking DATABASE_URL configuration...")
if not DATABASE_URL:
    logger.warning("DATABASE_URL environment variable is not set!")
    # Временное решение для отладки - использовать тестовую базу данных
    if os.getenv("RENDER") == "true":
        # Если мы на Render.com, выводим больше информации для диагностики
        logger.error("Running on Render.com but DATABASE_URL is not set!")
        logger.error("This might indicate that the database is not properly linked")
        logger.error("Please check if the database exists and is properly configured in render.yaml")
        raise ValueError("DATABASE_URL environment variable is not set on Render.com")
    else:
        # Локально используем тестовую базу
        logger.warning("Using fallback local database for development")
        DATABASE_URL = "postgresql://postgres:123456@localhost:5432/totp_db"

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
    
    # Добавляем параметры SSL только для Render.com
    if os.getenv("RENDER") == "true":
        logger.info("Adding SSL parameters for Render.com deployment")
        query_params.update({
            "sslmode": ["require"],
        })
    
    new_query = urllib.parse.urlencode(query_params, doseq=True)
    db_url = urllib.parse.urlunparse(
        parsed_url._replace(query=new_query)
    )
    
    # Логируем URL без чувствительных данных
    safe_url = db_url.split('@')[0] + '@' + db_url.split('@')[1].split('?')[0]
    logger.info(f"Database URL configured: {safe_url}")
    return db_url

def create_db_engine(retries=5, delay=5):
    last_exception = None
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
            
            # Проверяем подключение
            with engine.connect() as connection:
                connection.execute("SELECT 1")
            logger.info("Database engine created successfully")
            return engine
        except Exception as e:
            last_exception = e
            logger.error(f"Failed to create database engine: {str(e)}")
            if attempt < retries - 1:
                logger.info(f"Retrying in {delay} seconds...")
                time.sleep(delay)
            else:
                logger.error("Max retries reached, raising last exception")
                raise last_exception

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