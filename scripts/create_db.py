
import logging
import sqlite3

from sqlalchemy.exc import OperationalError

from auth.database import engine
from auth.models.sql import Base

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def create_tables():
    # ... (rest of the function)
    try:
        Base.metadata.create_all(bind=engine, checkfirst=True)
        logger.info("Tables created successfully.")
    except (OperationalError, sqlite3.OperationalError):
        # ... (rest of the except block)
        logger.info("Tables already exist.")

if __name__ == "__main__":
    create_tables()
