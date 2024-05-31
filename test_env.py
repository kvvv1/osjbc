from dotenv import load_dotenv
import os

# Carregar variáveis do arquivo sendgrid.env com caminho absoluto
env_loaded = load_dotenv('C:/Users/kaike/Desktop/PROGRAMA - OS/sendgrid.env')

if not env_loaded:
    print("Erro ao carregar o arquivo sendgrid.env")

# Verificar se a variável de ambiente foi carregada
sendgrid_api_key = os.getenv('SENDGRID_API_KEY')

if sendgrid_api_key:
    print(f"SENDGRID_API_KEY: {sendgrid_api_key}")
else:
    print("SENDGRID_API_KEY não foi carregada")
