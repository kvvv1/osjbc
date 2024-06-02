import os
import shutil
import sqlite3
from datetime import datetime, timedelta
import pytz
import base64
import logging
from logging.handlers import RotatingFileHandler
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, g
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import sendgrid
from sendgrid.helpers.mail import Mail, Attachment, FileContent, FileName, FileType, Disposition
from forms import LoginForm, RegisterForm, OSForm, EditOSForm
from celery_config import make_celery
from config import Config

def get_current_brasilia_time():
    brasilia_tz = pytz.timezone('America/Sao_Paulo')
    now_brasilia = datetime.now(brasilia_tz)
    return now_brasilia.strftime('%d/%m/%Y %H:%M:%S')

def create_tables():
    conn = sqlite3.connect('site.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            phone TEXT NOT NULL,
            sector TEXT NOT NULL
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS os (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_path TEXT NOT NULL,
            created_at TEXT NOT NULL,
            name TEXT,
            creator_id INTEGER,
            ultima_notificacao TEXT,
            status TEXT DEFAULT 'PENDENTE',
            FOREIGN KEY(creator_id) REFERENCES users(id)
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS sector (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            viewed INTEGER NOT NULL DEFAULT 0,
            viewed_at TEXT,
            os_id INTEGER,
            user_id INTEGER,
            accepted_by TEXT,
            accepted_at TEXT,
            status TEXT DEFAULT 'PENDENTE',
            FOREIGN KEY(os_id) REFERENCES os(id),
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS observations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            os_id INTEGER,
            sector TEXT,
            observation TEXT,
            responsible TEXT,
            created_at TEXT,
            FOREIGN KEY(os_id) REFERENCES os(id)
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            message TEXT,
            is_read INTEGER DEFAULT 0,
            created_at TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    ''')
    conn.commit()
    c.execute('SELECT * FROM users WHERE username = ?', ('kaike.vittor',))
    admin = c.fetchone()
    if not admin:
        hashed_password = generate_password_hash('794613852', method='sha256')
        c.execute('''
            INSERT INTO users (username, password, email, phone, sector)
            VALUES (?, ?, ?, ?, ?)
        ''', ('kaike.vittor', hashed_password, 'kaike.vittor@example.com', '1234567890', 'ADMIN'))
        conn.commit()
    conn.close()

def add_column_if_not_exists():
    conn = sqlite3.connect('site.db')
    c = conn.cursor()
    
    # Verificar se a coluna 'ultima_notificacao' já existe
    c.execute("PRAGMA table_info(os)")
    columns = [column[1] for column in c.fetchall()]
    if 'ultima_notificacao' not in columns:
        c.execute('ALTER TABLE os ADD COLUMN ultima_notificacao TEXT')
        conn.commit()
    
    conn.close()

def add_column_status_if_not_exists():
    conn = sqlite3.connect('site.db')
    c = conn.cursor()
    
    # Verificar se a coluna 'status' já existe
    c.execute("PRAGMA table_info(os)")
    columns = [column[1] for column in c.fetchall()]
    if 'status' not in columns:
        c.execute('ALTER TABLE os ADD COLUMN status TEXT DEFAULT "PENDENTE"')
        conn.commit()
    
    conn.close()

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    app.secret_key = app.config['SECRET_KEY']
    app.config['UPLOAD_FOLDER'] = os.path.join('static', 'uploads')
    app.config['MAX_CONTENT_PATH'] = 16 * 1024 * 1024  # Limite de tamanho do arquivo para 16MB, ajuste conforme necessário

    # Configuração de Celery
    app.config.update(
        CELERY_BROKER_URL=app.config['CELERY_BROKER_URL'],
        CELERY_RESULT_BACKEND=app.config['CELERY_RESULT_BACKEND'],
    )
    celery = make_celery(app)

    # Configuração de login
    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = 'login'

    # Configuração do log
    if not os.path.exists('logs'):
        os.mkdir('logs')
    file_handler = RotatingFileHandler('logs/app.log', maxBytes=10240, backupCount=10)
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'))
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)
    app.logger.info('Iniciando a aplicação')

    @app.before_first_request
    def initialize_database():
        create_tables()
        add_column_if_not_exists()
        add_column_status_if_not_exists()

    # Criar o diretório de uploads se não existir
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])

    # Função para enviar notificações por e-mail usando SendGrid
    def send_email_notification(email, subject, message, os_id):
        sg = sendgrid.SendGridAPIClient(api_key=app.config['SENDGRID_API_KEY'])
        host_url = "http://localhost:5000"  # Altere para o host futuro
        current_year = datetime.utcnow().year

        html_content = render_template('email_template.html', message=message, os_id=os_id, host_url=host_url, current_year=current_year)
        mail = Mail(
            from_email=app.config['SENDER_EMAIL'],
            to_emails=email,
            subject=subject,
            html_content=html_content
        )

        # Adicionar a imagem da logo como anexo
        with open('static/images/logoemail.png', 'rb') as img:
            img_data = img.read()
            encoded_img = base64.b64encode(img_data).decode()
            attachment = Attachment(
                file_content=FileContent(encoded_img),
                file_name=FileName('logoemail.png'),
                file_type=FileType('image/png'),
                disposition=Disposition('inline'),
                content_id='logoemail'
            )
            mail.add_attachment(attachment)

        try:
            response = sg.send(mail)
            print(f"Email enviado para {email} com status {response.status_code}")
            print(f"Corpo da resposta: {response.body}")
            print(f"Cabeçalhos da resposta: {response.headers}")
            return response.status_code, response.body, response.headers
        except Exception as e:
            print(f"Erro ao enviar email para {email} pelo SendGrid: {e}")
            return None, None, None

    @login_manager.user_loader
    def load_user(user_id):
        conn = sqlite3.connect('site.db')
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE id = ?', (user_id,))
        user = c.fetchone()
        conn.close()
        if user:
            user_obj = UserMixin()
            user_obj.id = user[0]
            user_obj.username = user[1]
            user_obj.password = user[2]
            user_obj.email = user[3]
            user_obj.phone = user[4]
            user_obj.sector = user[5]  # Certifique-se de que o setor está sendo carregado
            return user_obj
        return None

    @app.before_request
    def before_request():
        if current_user.is_authenticated:
            conn = sqlite3.connect('site.db')
            c = conn.cursor()
            c.execute('SELECT COUNT(*) FROM notifications WHERE user_id = ? AND is_read = 0', (current_user.id,))
            g.unread_notifications_count = c.fetchone()[0]
            conn.close()
        else:
            g.unread_notifications_count = 0

    @app.route('/')
    @login_required
    def index():
        conn = sqlite3.connect('site.db')
        conn.row_factory = sqlite3.Row  # Permite acessar os resultados como dicionário
        c = conn.cursor()
        c.execute('''
            SELECT os.id, os.file_path, os.created_at, os.name, os.creator_id, users.username,
               os.status,
               GROUP_CONCAT(DISTINCT sector.name) AS sectors
        FROM os
        JOIN users ON os.creator_id = users.id
        LEFT JOIN sector ON os.id = sector.os_id
        GROUP BY os.id, os.file_path, os.created_at, os.name, os.creator_id, users.username, os.status
        ORDER BY os.created_at DESC
    ''')        
        orders = c.fetchall()

        # Contador de notificações não lidas
        c.execute('SELECT COUNT(*) FROM notifications WHERE user_id = ? AND is_read = 0', (current_user.id,))
        unread_notifications_count = c.fetchone()[0]

        conn.close()

        return render_template('index.html', orders=orders, unread_notifications_count=unread_notifications_count)

    # Função para verificar se o arquivo é permitido
    def allowed_file(filename):
        return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'pdf'}

    @app.route('/register', methods=['GET', 'POST'])
    @login_required
    def register():
        if current_user.username != 'kaike.vittor':
            flash('Apenas o administrador pode registrar novos usuários.')
            return redirect(url_for('index'))
        form = RegisterForm()
        if form.validate_on_submit():
            hashed_password = generate_password_hash(form.password.data, method='sha256')
            conn = sqlite3.connect('site.db')
            c = conn.cursor()
            c.execute('''
                INSERT INTO users (username, password, email, phone, sector)
                VALUES (?, ?, ?, ?, ?)
            ''', (form.username.data, hashed_password, form.email.data, form.phone.data, form.sector.data))
            conn.commit()
            conn.close()
            flash('Usuário registrado com sucesso!')
            return redirect(url_for('index'))
        return render_template('register.html', form=form)

    @app.route('/logout')
    @login_required
    def logout():
        logout_user()
        return redirect(url_for('login'))

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        form = LoginForm()
        if form.validate_on_submit():
            conn = sqlite3.connect('site.db')
            c = conn.cursor()
            c.execute('SELECT * FROM users WHERE username = ?', (form.username.data,))
            user = c.fetchone()
            conn.close()
            if user and check_password_hash(user[2], form.password.data):
                user_obj = UserMixin()
                user_obj.id = user[0]
                user_obj.username = user[1]
                user_obj.password = user[2]
                user_obj.email = user[3]
                user_obj.phone = user[4]
                user_obj.sector = user[5]
                login_user(user_obj, remember=form.remember_me.data)
                return redirect(url_for('index'))
            flash('Login inválido. Verifique seu usuário e senha.')
        return render_template('login.html', form=form)

    @app.route('/create', methods=['GET', 'POST'])
    @login_required
    def create_os():
        form = OSForm()
        if form.validate_on_submit():
            file = form.file.data
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)

                relative_file_path = filename  # Salvamos apenas o nome do arquivo
                created_at = get_current_brasilia_time()
                conn = sqlite3.connect('site.db')
                c = conn.cursor()
                c.execute('''
                    INSERT INTO os (file_path, created_at, name, creator_id)
                    VALUES (?, ?, ?, ?)
                ''', (relative_file_path, created_at, form.name.data, current_user.id))
                os_id = c.lastrowid
                conn.commit()

                sectors = []
                if form.rh.data:
                    sectors.append('RH')
                if form.semst.data:
                    sectors.append('SEMST')
                if form.comercial.data:
                    sectors.append('COMERCIAL')
                if form.financeiro.data:
                    sectors.append('FINANCEIRO')
                if form.suprimentos.data:
                    sectors.append('SUPRIMENTOS')
                if form.operacional.data:
                    sectors.append('OPERACIONAL')
                if form.dp.data:
                    sectors.append('DP')
                if form.recepcao.data:
                    sectors.append('RECEPÇÃO')
                if form.ti.data:
                    sectors.append('TI')

                for sector_name in sectors:
                    c.execute('SELECT id FROM users WHERE sector = ?', (sector_name,))
                    users = c.fetchall()
                    for user in users:
                        c.execute('''
                            INSERT INTO sector (name, os_id, user_id)
                            VALUES (?, ?, ?)
                        ''', (sector_name, os_id, user[0]))
                    conn.commit()

                    for user in users:
                        c.execute('SELECT email FROM users WHERE id = ?', (user[0],))
                        chief_email = c.fetchone()[0]
                        message = f'A Ordem de Serviço foi criada. Verifique a OS anexada.'
                        send_email_notification(chief_email, 'Nova OS Criada', message, os_id)
                        c.execute('''
                            INSERT INTO notifications (user_id, message, created_at)
                            VALUES (?, ?, ?)
                        ''', (user[0], f'Nova OS criada: {form.name.data}', created_at))
                    conn.commit()

                conn.close()
                flash('Ordem de serviço criada com sucesso!')
                return redirect(url_for('index'))
        return render_template('create_os.html', form=form)

    @app.route('/view/<int:os_id>', methods=['GET', 'POST'])
    @login_required
    def view_os(os_id):
        conn = sqlite3.connect('site.db')
        conn.row_factory = sqlite3.Row
        c = conn.cursor()

        c.execute('SELECT * FROM os WHERE id = ?', (os_id,))
        order = c.fetchone()

        if not order:
            flash('Ordem de serviço não encontrada.')
            return redirect(url_for('index'))

        c.execute('SELECT DISTINCT name FROM sector WHERE os_id = ?', (os_id,))
        sectors = c.fetchall()

        sector_data = []
        for sector in sectors:
            c.execute('''
                SELECT users.username, sector.viewed, sector.accepted_at, users.id AS user_id, sector.id AS sector_id 
                FROM users 
                JOIN sector ON users.id = sector.user_id 
                WHERE sector.os_id = ? AND sector.name = ?
            ''', (os_id, sector['name']))
            users = c.fetchall()
            sector_data.append({
                'name': sector['name'],
                'users': [{'username': user['username'], 'viewed': user['viewed'], 'accepted_at': user['accepted_at'], 'user_id': user['user_id'], 'sector_id': user['sector_id']} for user in users]
            })

        c.execute('SELECT id, username FROM users WHERE id = ?', (order['creator_id'],))
        creator = c.fetchone()

        c.execute('SELECT id, os_id, sector, observation, responsible, created_at FROM observations WHERE os_id = ?', (os_id,))
        observations = c.fetchall()

        conn.close()

        return render_template('view_os.html', order=dict(order), sectors=sector_data, creator=dict(creator), observations=[dict(observation) for observation in observations], is_creator=current_user.id == order['creator_id'])

    @app.route('/uploads/<path:filename>')
    @login_required
    def uploaded_file(filename):
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

    @app.route('/download/<int:id>')
    @login_required
    def download_file(id):
        # Consultar o caminho do arquivo no banco de dados
        conn = sqlite3.connect('site.db')
        cursor = conn.cursor()
        cursor.execute("SELECT file_path FROM os WHERE id = ?", (id,))
        file_path = cursor.fetchone()[0]
        conn.close()

        # O caminho no banco de dados é relativo à pasta 'static/uploads'
        filename = os.path.basename(file_path)

        # Servir o arquivo para download
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)

    @app.route('/mark_viewed/<int:sector_id>')
    @login_required
    def mark_viewed(sector_id):
        viewed_at = get_current_brasilia_time()
        conn = sqlite3.connect('site.db')
        c = conn.cursor()
        c.execute('UPDATE sector SET viewed = 1, viewed_at = ? WHERE id = ?', (viewed_at, sector_id))
        conn.commit()
        c.execute('SELECT os_id FROM sector WHERE id = ?', (sector_id,))
        os_id = c.fetchone()[0]

        # Verificar se todos aceitaram
        c.execute('SELECT COUNT(*) FROM sector WHERE os_id = ? AND (viewed = 0 OR accepted_by IS NULL)', (os_id,))
        pending_count = c.fetchone()[0]
        if pending_count == 0:
            c.execute('UPDATE os SET status = "FINALIZADO" WHERE id = ?', (os_id,))
        else:
            c.execute('UPDATE os SET status = "PENDENTE" WHERE id = ?', (os_id,))

        conn.close()
        return redirect(url_for('view_os', os_id=os_id))

    @app.route('/manage', methods=['GET', 'POST'])
    @login_required
    def manage():
        if current_user.username != 'kaike.vittor':
            flash('Acesso negado.')
            return redirect(url_for('index'))

        conn = sqlite3.connect('site.db')
        c = conn.cursor()

        if request.method == 'POST':
            username = request.form.get('username')
            password = request.form.get('password')
            email = request.form.get('email')
            phone = request.form.get('phone')
            sector = request.form.get('sector')

            # Verificar se o e-mail já existe
            c.execute('SELECT * FROM users WHERE email = ?', (email,))
            existing_user = c.fetchone()
            if existing_user:
                flash('O e-mail já está em uso. Por favor, use um e-mail diferente.')
            else:
                hashed_password = generate_password_hash(password, method='sha256')
                c.execute('''
                    INSERT INTO users (username, password, email, phone, sector)
                    VALUES (?, ?, ?, ?, ?)
                ''', (username, hashed_password, email, phone, sector))
                conn.commit()
                flash('Usuário adicionado com sucesso!')

        c.execute('SELECT * FROM users')
        users = c.fetchall()

        c.execute('SELECT DISTINCT sector FROM users')
        sectors = c.fetchall()
        sector_data = []
        for sector in sectors:
            c.execute('SELECT username FROM users WHERE sector = ?', (sector[0],))
            sector_users = c.fetchall()
            sector_data.append({'name': sector[0], 'users': [{'username': user[0]} for user in sector_users]})

        conn.close()
        return render_template('manage.html', users=users, sectors=sector_data)

    @app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
    @login_required
    def edit_user(user_id):
        if current_user.username != 'kaike.vittor':
            flash('Acesso negado.')
            return redirect(url_for('index'))

        conn = sqlite3.connect('site.db')
        c = conn.cursor()

        if request.method == 'POST':
            username = request.form.get('username')
            email = request.form.get('email')
            phone = request.form.get('phone')
            sector = request.form.get('sector')

            c.execute('''
                UPDATE users
                SET username = ?, email = ?, phone = ?, sector = ?
                WHERE id = ?
            ''', (username, email, phone, sector, user_id))
            conn.commit()
            conn.close()
            flash('Informações do usuário atualizadas com sucesso.')
            return redirect(url_for('manage'))

        c.execute('SELECT * FROM users WHERE id = ?', (user_id,))
        user = c.fetchone()
        conn.close()
        
        if not user:
            flash('Usuário não encontrado.')
            return redirect(url_for('manage'))

        return render_template('edit_user.html', user=user)

    @app.route('/clear_os', methods=['POST'])
    @login_required
    def clear_os():
        if current_user.username != 'kaike.vittor':
            flash('Acesso negado.')
            return redirect(url_for('index'))

        backup_folder = 'backup'
        if not os.path.exists(backup_folder):
            os.makedirs(backup_folder)

        # Criar backup do banco de dados
        backup_file = os.path.join(backup_folder, f'site_backup_{get_current_brasilia_time().replace("/", "").replace(":", "").replace(" ", "")}.db')
        shutil.copy2('site.db', backup_file)

        conn = sqlite3.connect('site.db')
        c = conn.cursor()
        c.execute('DELETE FROM os')
        c.execute('DELETE FROM sector')
        conn.commit()
        conn.close()
        flash('Todas as ordens de serviço foram removidas com sucesso. Um backup foi criado.')
        return redirect(url_for('manage'))

    @app.route('/delete_user/<int:user_id>', methods=['POST'])
    @login_required
    def delete_user(user_id):
        if current_user.username != 'kaike.vittor':
            flash('Acesso negado.')
            return redirect(url_for('index'))

        conn = sqlite3.connect('site.db')
        c = conn.cursor()
        c.execute('DELETE FROM users WHERE id = ?', (user_id,))
        conn.commit()
        conn.close()
        flash('Usuário removido com sucesso.')
        return redirect(url_for('manage'))

    @app.route('/return/<int:sector_id>', methods=['POST'])
    @login_required
    def return_os(sector_id):
        observation = request.form.get('observation')
        responsible = current_user.username
        created_at = get_current_brasilia_time()

        conn = sqlite3.connect('site.db')
        c = conn.cursor()

        try:
            # Obter os_id e nome do setor a partir do sector_id
            c.execute('SELECT os_id, name FROM sector WHERE id = ?', (sector_id,))
            result = c.fetchone()
            if not result:
                flash('Setor não encontrado.')
                return redirect(url_for('index'))

            os_id, sector_name = result

            # Inserir observação de recusa
            c.execute('''
                INSERT INTO observations (os_id, sector, observation, responsible, created_at)
                VALUES (?, ?, ?, ?, ?)
            ''', (os_id, sector_name, 'Recusa: ' + observation, responsible, created_at))

            # Atualizar o status do setor para recusado
            c.execute('UPDATE sector SET status = "RECUSADO", viewed = 0, accepted_by = ?, accepted_at = ? WHERE id = ?', (responsible, created_at, sector_id))

            # Obter informações do criador da OS
            c.execute('SELECT creator_id FROM os WHERE id = ?', (os_id,))
            creator_id = c.fetchone()[0]
            c.execute('SELECT email FROM users WHERE id = ?', (creator_id,))
            creator_email = c.fetchone()[0]
            c.execute('SELECT name FROM os WHERE id = ?', (os_id,))
            os_name = c.fetchone()[0]

            # Atualizar o status da OS para pendente
            c.execute('UPDATE os SET status = "PENDENTE" WHERE id = ?', (os_id,))

            conn.commit()
            conn.close()

            # Enviar e-mail de retorno para o criador da OS com observações dos setores
            subject = 'Retorno sobre a OS'
            message = f'A Ordem de Serviço <strong>{os_name}</strong> foi retornada pelo setor <strong>{sector_name}</strong> com a seguinte observação: {observation}.'
            send_email_notification(creator_email, subject, message, os_id)

            # Adicionar notificação para o criador da OS
            conn = sqlite3.connect('site.db')
            c = conn.cursor()
            c.execute('''
                INSERT INTO notifications (user_id, message, created_at)
                VALUES (?, ?, ?)
            ''', (creator_id, f'Retorno sobre a OS {os_name}: {observation}', created_at))
            conn.commit()
            conn.close()

        except Exception as e:
            print(f"Error: {e}")
            flash('Ocorreu um erro ao processar a recusa. Tente novamente.')
            conn.close()

        flash('Observação enviada ao criador da OS.')
        return redirect(url_for('view_os', os_id=os_id))

    @app.route('/add_observation/<int:os_id>', methods=['POST'])
    @login_required
    def add_observation(os_id):
        observation = request.form.get('observation')
        sector = current_user.sector
        responsible = current_user.username
        created_at = get_current_brasilia_time()

        conn = sqlite3.connect('site.db')
        c = conn.cursor()

        try:
            # Inserir observação
            c.execute('''
                INSERT INTO observations (os_id, sector, observation, responsible, created_at)
                VALUES (?, ?, ?, ?, ?)
            ''', (os_id, sector, observation, responsible, created_at))

            # Obter informações do criador da OS
            c.execute('SELECT creator_id FROM os WHERE id = ?', (os_id,))
            creator_id = c.fetchone()[0]
            c.execute('SELECT email FROM users WHERE id = ?', (creator_id,))
            creator_email = c.fetchone()[0]
            c.execute('SELECT name FROM os WHERE id = ?', (os_id,))
            os_name = c.fetchone()[0]

            conn.commit()
            conn.close()

            # Enviar e-mail de observação para o criador da OS
            subject = 'Nova Observação na OS'
            message = f'A Ordem de Serviço <strong>{os_name}</strong> recebeu uma nova observação do setor <strong>{sector}</strong>: {observation}.'
            send_email_notification(creator_email, subject, message, os_id)

            # Adicionar notificação para o criador da OS
            conn = sqlite3.connect('site.db')
            c = conn.cursor()
            c.execute('''
                INSERT INTO notifications (user_id, message, created_at)
                VALUES (?, ?, ?)
            ''', (creator_id, f'Nova observação na OS {os_name}: {observation}', created_at))
            conn.commit()
            conn.close()

        except Exception as e:
            print(f"Error: {e}")
            flash('Ocorreu um erro ao adicionar a observação. Tente novamente.')
            conn.close()

        flash('Observação adicionada com sucesso.')
        return redirect(url_for('view_os', os_id=os_id))

    @app.route('/notifications')
    @login_required
    def notifications():
        conn = sqlite3.connect('site.db')
        c = conn.cursor()
        c.execute('SELECT * FROM notifications WHERE user_id = ? ORDER BY created_at DESC', (current_user.id,))
        notifications = c.fetchall()
        conn.close()
        return render_template('notifications.html', notifications=notifications)

    @app.route('/notifications/mark_as_read/<int:notification_id>')
    @login_required
    def mark_as_read(notification_id):
        conn = sqlite3.connect('site.db')
        c = conn.cursor()
        c.execute('UPDATE notifications SET is_read = 1 WHERE id = ?', (notification_id,))
        conn.commit()
        conn.close()
        return redirect(url_for('notifications'))

    @app.route('/accept/<int:sector_id>', methods=['POST'])
    @login_required
    def accept_os(sector_id):
        accepted_at = get_current_brasilia_time()
        conn = sqlite3.connect('site.db')
        c = conn.cursor()
        c.execute('UPDATE sector SET viewed = 1, accepted_by = ?, accepted_at = ? WHERE id = ? AND user_id = ?', (current_user.username, accepted_at, sector_id, current_user.id))
        c.execute('SELECT os_id FROM sector WHERE id = ?', (sector_id,))
        os_id = c.fetchone()[0]

        # Verificar se todos aceitaram
        c.execute('SELECT COUNT(*) FROM sector WHERE os_id = ? AND (viewed = 0 OR accepted_by IS NULL)', (os_id,))
        pending_count = c.fetchone()[0]
        if pending_count == 0:
            c.execute('UPDATE os SET status = "FINALIZADO" WHERE id = ?', (os_id,))
        else:
            c.execute('UPDATE os SET status = "PENDENTE" WHERE id = ?', (os_id,))

        conn.commit()
        conn.close()
        return redirect(url_for('view_os', os_id=os_id))

    @app.route('/history')
    @login_required
    def history():
        conn = sqlite3.connect('site.db')
        conn.row_factory = sqlite3.Row  # Isso permite que você acesse os resultados como um dicionário
        c = conn.cursor()

        query = '''
        SELECT os.id, os.name, os.created_at, users.username, 
               os.status,
               GROUP_CONCAT(DISTINCT sector.name ORDER BY sector.name ASC) AS sectors
        FROM os
        JOIN users ON os.creator_id = users.id
        LEFT JOIN sector ON os.id = sector.os_id
        WHERE 1=1
    '''
        params = []

        search = request.args.get('search')
        if search:
            query += ' AND os.name LIKE ?'
            params.append(f'%{search}%')

        filter_by_creator = request.args.get('filter_by_creator')
        if filter_by_creator:
            query += ' AND users.username = ?'
            params.append(filter_by_creator)

        filter_year = request.args.get('filter_year')
        if filter_year:
            query += ' AND strftime("%Y", os.created_at) = ?'
            params.append(filter_year)

        filter_month = request.args.get('filter_month')
        if filter_month:
            query += ' AND strftime("%m", os.created_at) = ?'
            params.append(f'{int(filter_month):02d}')  # Garantir que o mês tenha dois dígitos

        filter_status = request.args.get('filter_status')
        if filter_status:
            query += ' AND os.status = ?'
            params.append(filter_status)

        query += ' GROUP BY os.id, os.name, os.created_at, users.username'

        c.execute(query, params)
        orders = c.fetchall()

        c.execute('SELECT DISTINCT username FROM users')
        creators = c.fetchall()

        conn.close()

        # Converte os resultados em uma lista de dicionários
        orders = [dict(order) for order in orders]

        return render_template('history.html', orders=orders, creators=creators)

    @app.route('/resend/<int:os_id>', methods=['POST'])
    @login_required
    def resend_os(os_id):
        conn = sqlite3.connect('site.db')
        c = conn.cursor()

        # Obter dados da OS
        c.execute('SELECT * FROM os WHERE id = ?', (os_id,))
        order = c.fetchone()

        if order[4] != current_user.id:
            flash('Você não tem permissão para reenviar esta OS.')
            conn.close()
            return redirect(url_for('view_os', os_id=os_id))

        # Redefinir os campos de aceitação
        c.execute('UPDATE sector SET viewed = 0, accepted_by = NULL, accepted_at = NULL WHERE os_id = ?', (os_id,))
        conn.commit()

        # Notificar todos os setores selecionados
        c.execute('SELECT DISTINCT name FROM sector WHERE os_id = ?', (os_id,))
        sectors = c.fetchall()

        created_at = get_current_brasilia_time()
        for sector in sectors:
            c.execute('SELECT id FROM users WHERE sector = ?', (sector[0],))
            users = c.fetchall()
            for user in users:
                c.execute('SELECT email FROM users WHERE id = ?', (user[0],))
                chief_email = c.fetchone()[0]
                message = f'A OS {order[3]} foi atualizada. Verifique o arquivo PDF anexado.'
                send_email_notification(chief_email, 'OS Atualizada', message, os_id)
                c.execute('''
                    INSERT INTO notifications (user_id, message, created_at)
                    VALUES (?, ?, ?)
                ''', (user[0], f'A OS {order[3]} foi atualizada. Por favor, aceite novamente.', created_at))
            conn.commit()

        conn.close()
        flash('OS reenviada e notificação enviada a todos os setores selecionados. Todos devem aceitar novamente.')
        return redirect(url_for('view_os', os_id=os_id))

    @app.route('/edit/<int:os_id>', methods=['GET', 'POST'])
    @login_required
    def edit_os(os_id):
        conn = sqlite3.connect('site.db')
        c = conn.cursor()
        c.execute('SELECT * FROM os WHERE id = ?', (os_id,))
        order = c.fetchone()

        if order[4] != current_user.id:
            flash('Você não tem permissão para editar esta OS.')
            conn.close()
            return redirect(url_for('view_os', os_id=os_id))

        if order[6] == 'FINALIZADO':
            flash('Você não pode editar uma OS que está finalizada.')
            conn.close()
            return redirect(url_for('view_os', os_id=os_id))

        form = EditOSForm()
        if form.validate_on_submit():
            # Atualizar o nome da OS
            c.execute('UPDATE os SET name = ? WHERE id = ?', (form.name.data, os_id))

            # Upload do novo arquivo, se fornecido
            if form.file.data and allowed_file(form.file.data.filename):
                filename = secure_filename(form.file.data.filename)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                form.file.data.save(file_path)

                relative_file_path = filename  # Salvamos apenas o nome do arquivo
                c.execute('UPDATE os SET file_path = ? WHERE id = ?', (relative_file_path, os_id))

            conn.commit()
            conn.close()
            flash('OS atualizada com sucesso!')
            return redirect(url_for('view_os', os_id=os_id))

        form.name.data = order[3]
        conn.close()
        return render_template('edit_os.html', form=form, order={
            'id': order[0],
            'file_path': order[1],
            'created_at': order[2],
            'name': order[3]
        })

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
else:
    app = create_app()
