import sqlite3

def add_user_id_column():
    conn = sqlite3.connect('site.db')
    c = conn.cursor()
    try:
        c.execute('ALTER TABLE sector ADD COLUMN user_id INTEGER')
        conn.commit()
        print("Coluna 'user_id' adicionada com sucesso.")
    except sqlite3.OperationalError as e:
        print(f"Erro ao adicionar a coluna 'user_id': {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    add_user_id_column()
