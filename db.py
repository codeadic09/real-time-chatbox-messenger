import mysql.connector

def get_connection():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="Omcf1318",          # XAMPP default
        database="login_py",
        port=3306              # change to 3307 if needed
    )
