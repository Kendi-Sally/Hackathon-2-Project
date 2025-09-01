import mysql.connector
from dotenv import load_dotenv
import os

load_dotenv()

DB_HOST = os.getenv('DB_HOST','localhost')
DB_USER = os.getenv('DB_USER','root')
DB_PASSWORD = os.getenv('DB_PASSWORD','')

conn = mysql.connector.connect(host=DB_HOST, user=DB_USER, password=DB_PASSWORD)
cur = conn.cursor()

cur.execute("CREATE DATABASE IF NOT EXISTS flashcards_db;")
cur.execute("USE flashcards_db;")

cur.execute('''
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(100) NOT NULL UNIQUE,
    email VARCHAR(100) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    is_premium BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
''')

cur.execute('''
CREATE TABLE IF NOT EXISTS flashcards (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    question TEXT NOT NULL,
    answer TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
''')

print('✅ Database and tables created (flashcards_db)')
cur.close()
conn.close()
