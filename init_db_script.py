import logging
import sys
from app.init_db import init_db

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

if __name__ == "__main__":
    try:
        init_db()
        logger.info("Инициализация базы данных успешно завершена!")
    except Exception as e:
        logger.error(f"Ошибка при инициализации базы данных: {str(e)}")
        sys.exit(1) 