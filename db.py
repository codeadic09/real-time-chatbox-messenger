import mysql.connector
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def get_connection():
    """Create and return a secure database connection"""
    try:
        connection = mysql.connector.connect(
            host=os.getenv('DB_HOST', 'localhost'),
            user=os.getenv('DB_USER', 'root'),
            password=os.getenv('DB_PASSWORD'),
            database=os.getenv('DB_NAME', 'login_py'),
            port=int(os.getenv('DB_PORT', 3306)),
            autocommit=False,
            use_pure=True,
            charset='utf8mb4',
            collation='utf8mb4_unicode_ci'
        )
        return connection
    except mysql.connector.Error as err:
        print(f"Database connection error: {err}")
        raise
