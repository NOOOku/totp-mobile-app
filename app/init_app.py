from .database import engine, Base
from . import models
import logging

logger = logging.getLogger(__name__)

def init_app():
    try:
        logger.info("Creating database tables...")
        Base.metadata.create_all(bind=engine)
        logger.info("Database tables created successfully!")
    except Exception as e:
        logger.error(f"Error creating database tables: {str(e)}")
        raise 