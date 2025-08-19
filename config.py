"""
Configuration settings for SecureWatch IDS
"""
import os
from datetime import timedelta

class Config:
    """Base configuration class"""
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///ids_database.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # IDS Configuration
    PACKET_CAPTURE_INTERFACE = os.environ.get('CAPTURE_INTERFACE') or 'eth0'
    MAX_EVENTS_MEMORY = int(os.environ.get('MAX_EVENTS_MEMORY', 10000))
    ALERT_RETENTION_DAYS = int(os.environ.get('ALERT_RETENTION_DAYS', 30))
    LOG_RETENTION_DAYS = int(os.environ.get('LOG_RETENTION_DAYS', 90))
    
    # Threat Detection Thresholds
    PORT_SCAN_THRESHOLD = int(os.environ.get('PORT_SCAN_THRESHOLD', 10))
    BRUTE_FORCE_THRESHOLD = int(os.environ.get('BRUTE_FORCE_THRESHOLD', 5))
    DDOS_THRESHOLD = int(os.environ.get('DDOS_THRESHOLD', 100))
    
    # Alert Configuration
    ENABLE_EMAIL_ALERTS = os.environ.get('ENABLE_EMAIL_ALERTS', 'False').lower() == 'true'
    SMTP_SERVER = os.environ.get('SMTP_SERVER')
    SMTP_PORT = int(os.environ.get('SMTP_PORT', 587))
    SMTP_USERNAME = os.environ.get('SMTP_USERNAME')
    SMTP_PASSWORD = os.environ.get('SMTP_PASSWORD')
    ALERT_EMAIL_RECIPIENTS = os.environ.get('ALERT_EMAIL_RECIPIENTS', '').split(',')

class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    SQLALCHEMY_ECHO = True

class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    SQLALCHEMY_ECHO = False

# Configuration mapping
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}
