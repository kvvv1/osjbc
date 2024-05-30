import sqlite3
from werkzeug.security import generate_password_hash

# Conectar ao banco de dados
conn = sqlite3.connect('site.db')
c = conn.cursor()

# Adicionar o administrador
username = 'kaike.vittor'
password = '794613852'
hashed_password = generate_password_hash(password, method='sha256')
email = 'kaike.vittor@example.com'
phone = '1234567890'
sector = 'ADMIN'

# Inserir o administrador no banco de dados
c.execute('''
    INSERT INTO users (username, password, email, phone, sector)
    VALUES (?, ?, ?, ?, ?)
''', (username, hashed_password, email, phone, sector))
conn.commit()
conn.close()

print(f'Administrador {username} adicionado com sucesso.')
