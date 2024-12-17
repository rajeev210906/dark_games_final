import os
import sys

# Add your project directory to the sys.path
path = '/home/your_username/dark_games_final'
if path not in sys.path:
    sys.path.append(path)

from app import app as application
from app import init_db

# Initialize the database
init_db()

if __name__ == "__main__":
    application.run()
