from sqlalchemy_utils import database_exists, create_database
from sqlalchemy.exc import SQLAlchemyError
from .database import engine, SQLALCHEMY_DATABASE_URL, POSTGRES_DB
from . import models, schemas, crud
from .database import SessionLocal
import logging
import sys

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

def init_db():
    try:
        logger.info(f"Проверяем подключение к PostgreSQL...")
        conn = engine.connect()
        conn.close()
        logger.info("Подключение к PostgreSQL успешно!")
    except Exception as e:
        logger.error(f"Ошибка подключения к PostgreSQL: {str(e)}")
        raise

    try:
        logger.info(f"Проверяем существование базы данных {POSTGRES_DB}...")
        if not database_exists(engine.url):
            logger.info(f"База данных {POSTGRES_DB} не существует. Создаем...")
            create_database(engine.url)
            logger.info(f"База данных {POSTGRES_DB} успешно создана!")
        else:
            logger.info(f"База данных {POSTGRES_DB} уже существует")
    except Exception as e:
        logger.error(f"Ошибка при проверке/создании базы данных: {str(e)}")
        raise

    try:
        logger.info("Создаем таблицы...")
        models.Base.metadata.create_all(bind=engine)
        logger.info("Таблицы успешно созданы!")
    except Exception as e:
        logger.error(f"Ошибка при создании таблиц: {str(e)}")
        raise

    # Создаем тестового пользователя
    db = SessionLocal()
    try:
        logger.info("Создаем тестового пользователя...")
        test_user = schemas.UserCreate(
            username="test",
            email="test@example.com",
            password="test123"
        )
        
        # Проверяем, существует ли уже пользователь
        existing_user = crud.get_user_by_username(db, username=test_user.username)
        if existing_user:
            logger.info("Тестовый пользователь уже существует")
        else:
            user = crud.create_user(db, test_user)
            logger.info(f"Тестовый пользователь создан: {user.username}")
            
            # Создаем TOTP секрет для пользователя
            totp = crud.create_user_totp(db, user.id)
            logger.info(f"TOTP секрет создан для пользователя: {user.username}")
    except SQLAlchemyError as e:
        logger.error(f"Ошибка базы данных при создании тестового пользователя: {str(e)}")
        raise
    except Exception as e:
        logger.error(f"Неожиданная ошибка при создании тестового пользователя: {str(e)}")
        raise
    finally:
        db.close()
        logger.info("Соединение с базой данных закрыто")

if __name__ == "__main__":
    try:
        init_db()
        logger.info("Инициализация базы данных успешно завершена!")
    except Exception as e:
        logger.error(f"Ошибка при инициализации базы данных: {str(e)}")
        sys.exit(1) 