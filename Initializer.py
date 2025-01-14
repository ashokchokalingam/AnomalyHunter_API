import mysql.connector
from mysql.connector import Error
import logging
import os

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger()

# Database configuration using environment variables
db_config = {
    "host": os.getenv("DB_HOST", "localhost"),
    "user": os.getenv("DB_USER", "sigma"),
    "password": os.getenv("DB_PASSWORD", "sigma"),
    "database": os.getenv("DB_NAME", "sigma_db"),
}

def create_database():
    """Create the database if it doesn't exist."""
    connection = None
    try:
        connection = mysql.connector.connect(
            host=db_config['host'],
            user=db_config['user'],
            password=db_config['password']
        )
        cursor = connection.cursor()
        cursor.execute("CREATE DATABASE IF NOT EXISTS sigma_db")
        connection.commit()
        logger.info("Database 'sigma_db' created or already exists.")
    except Error as e:
        logger.error(f"Error creating database: {e}")
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()

def initialize_sql_tables():
    """Create the sigma_alerts table in the database if it doesn't exist."""
    connection = None
    try:
        connection = mysql.connector.connect(**db_config)
        if connection.is_connected():
            cursor = connection.cursor()
            create_sigma_alerts_query = """
            CREATE TABLE IF NOT EXISTS sigma_alerts (
                id INT AUTO_INCREMENT PRIMARY KEY,
                title VARCHAR(255),
                description TEXT,
                system_time DATETIME,
                computer_name VARCHAR(255),
                user_id VARCHAR(255),
                event_id VARCHAR(50),
                provider_name VARCHAR(255),
                ml_cluster INT DEFAULT NULL,
                ip_address VARCHAR(255),
                task VARCHAR(255),
                rule_level VARCHAR(50),
                target_user_name VARCHAR(255),
                target_domain_name VARCHAR(255),
                ruleid VARCHAR(255),
                raw TEXT,
                unique_hash VARCHAR(255),
                tactics TEXT,
                techniques TEXT,
                ml_description VARCHAR(4096),
                UNIQUE INDEX unique_log (unique_hash(255))
            );
            """
            cursor.execute(create_sigma_alerts_query)
            connection.commit()
            logger.info("Initialized SQL table 'sigma_alerts'.")
    except Error as e:
        logger.error(f"Error initializing SQL table: {e}")
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()

if __name__ == "__main__":
    create_database()
    initialize_sql_tables()
