import os

class Config:
    DEBUG = False
    TESTING = False
    DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///games.db')
    SECRET_KEY = os.environ.get('SECRET_KEY', 'your-secret-key-here')
    ADSENSE_ID = os.environ.get('ADSENSE_ID', '')

class ProductionConfig(Config):
    pass

class DevelopmentConfig(Config):
    DEBUG = True

class TestingConfig(Config):
    TESTING = True
