from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import os
import urllib.parse

# Получаем URL базы данных из переменной окружения или используем значение по умолчанию
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://postgres:123456@localhost:5432/totp_db")

# Обработка URL базы данных для поддержки SSL
def get_database_url():
    if DATABASE_URL.startswith("postgres://"):
        db_url = DATABASE_URL.replace("postgres://", "postgresql://")
    else:
        db_url = DATABASE_URL
    
    if "localhost" not in db_url:
        # Добавляем SSL параметры для production базы данных
        parsed_url = urllib.parse.urlparse(db_url)
        query_params = urllib.parse.parse_qs(parsed_url.query)
        query_params.update({
            "sslmode": ["require"],
        })
        new_query = urllib.parse.urlencode(query_params, doseq=True)
        db_url = urllib.parse.urlunparse(
            parsed_url._replace(query=new_query)
        )
    
    return db_url

engine = create_engine(
    get_database_url(),
    pool_pre_ping=True,
    pool_size=5,
    max_overflow=10,
    connect_args={
        "connect_timeout": 60,
    }
)

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