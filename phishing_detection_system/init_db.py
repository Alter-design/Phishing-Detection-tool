import os
import sqlite3

# Remove old database
if os.path.exists("phishing.db"):
    os.remove("phishing.db")
    print("Removed old database")

# Import and run init
from database import init_db
init_db()
