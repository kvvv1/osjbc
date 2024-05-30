import sqlite3

def add_columns():
    conn = sqlite3.connect('site.db')
    c = conn.cursor()
    try:
        c.execute('ALTER TABLE os ADD COLUMN file_path TEXT')
    except sqlite3.OperationalError:
        pass
    try:
        c.execute('ALTER TABLE os ADD COLUMN name TEXT')
    except sqlite3.OperationalError:
        pass
    try:
        c.execute('ALTER TABLE os ADD COLUMN creator_id INTEGER')
    except sqlite3.OperationalError:
        pass
    try:
        c.execute('ALTER TABLE sector ADD COLUMN user_id INTEGER')
    except sqlite3.OperationalError:
        pass
    try:
        c.execute('ALTER TABLE sector ADD COLUMN accepted_by TEXT')
    except sqlite3.OperationalError:
        pass
    try:
        c.execute('ALTER TABLE sector ADD COLUMN accepted_at TEXT')
    except sqlite3.OperationalError:
        pass
    try:
        c.execute('ALTER TABLE sector ADD COLUMN status TEXT')
    except sqlite3.OperationalError:
        pass
    try:
        c.execute('ALTER TABLE os ADD COLUMN ultima_notificacao TEXT')
    except sqlite3.OperationalError:
        pass
    try:
        c.execute('ALTER TABLE os ADD COLUMN status TEXT DEFAULT "PENDENTE"')
    except sqlite3.OperationalError:
        pass
    try:
        c.execute('ALTER TABLE notifications ADD COLUMN os_id INTEGER')
    except sqlite3.OperationalError:
        pass
    finally:
        conn.close()

if __name__ == "__main__":
    add_columns()
