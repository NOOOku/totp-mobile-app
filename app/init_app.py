from .database import engine, Base
from . import models
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

def init_app():
    try:
        logger.info("Starting database initialization...")
        logger.info("Checking database connection...")
        
        # Проверка подключения к базе данных
        with engine.connect() as connection:
            logger.info("Database connection successful")
            
        logger.info("Creating database tables...")
        Base.metadata.create_all(bind=engine)
        logger.info("Database tables created successfully!")
        
    except Exception as e:
        logger.error(f"Error during database initialization: {str(e)}")
        logger.error(f"Error type: {type(e).__name__}")
        logger.error(f"Error details: {str(e.args)}")
        raise 