from dotenv import load_dotenv
import os

# Especificar o caminho do arquivo key.env
load_dotenv('C:\\Users\\kaike\\Desktop\\SENDGRID\\sendgrid.env')

class Config:
    # Configurações básicas do Flask
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your_secret_key'
    UPLOAD_FOLDER = 'static/uploads'
    
    # Configurações do SendGrid
    SENDGRID_API_KEY = os.getenv('SENDGRID_API_KEY')
    SENDER_EMAIL = os.environ.get('SENDER_EMAIL') or 'kaikevns1@gmail.com'
    
    # CELERY CONFIGURATION
    CELERY_BROKER_URL = 'redis://localhost:6379/0'
    CELERY_RESULT_BACKEND = 'redis://localhost:6379/0'

    # Depuração para verificar se a chave foi carregada
    print(f'SENDGRID_API_KEY: {SENDGRID_API_KEY}')  # Depuração