from datetime import datetime, timedelta
from app import create_app
from flask import render_template
from celery_config import make_celery
import sqlite3
import sendgrid
from sendgrid.helpers.mail import Mail, Attachment, FileContent, FileName, FileType, Disposition
import base64

app = create_app()
celery = make_celery(app)

@celery.task
def add(x, y):
    return x + y

@celery.task
def send_reminders():
    with app.app_context():
        conn = sqlite3.connect('site.db')
        c = conn.cursor()
        c.execute('''
            SELECT os.id, os.name, os.creator_id, users.email, os.ultima_notificacao
            FROM os
            JOIN users ON os.creator_id = users.id
            WHERE os.status != "ACEITADO" AND (
                os.ultima_notificacao IS NULL OR
                datetime(os.ultima_notificacao) <= datetime('now', '-1 day')
            )
        ''')
        pending_orders = c.fetchall()

        for order in pending_orders:
            os_id, os_name, creator_id, email, ultima_notificacao = order

            # Enviar notificação no aplicativo
            send_app_notification(creator_id, f"Lembrete: A ordem de serviço {os_name} ainda não foi aceita.")

            # Enviar email
            subject = "Lembrete: Ordem de Serviço Pendente"
            message = f"Lembrete: A ordem de serviço <strong>{os_name}</strong> ainda não foi aceita. Por favor, tome as medidas necessárias."
            send_email_notification(email, subject, message, os_id)

            # Atualizar ultima_notificacao
            c.execute('UPDATE os SET ultima_notificacao = ? WHERE id = ?', (datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'), os_id))
            conn.commit()

        conn.close()

def send_app_notification(user_id, message):
    # Implementar lógica de envio de notificação interna no app
    pass

def send_email_notification(email, subject, message, os_id):
    sg = sendgrid.SendGridAPIClient(api_key=app.config['SENDGRID_API_KEY'])
    host_url = "http://localhost:5000"
    current_year = datetime.utcnow().year

    html_content = render_template('email_template.html', message=message, os_id=os_id, host_url=host_url, current_year=current_year)
    mail = Mail(
        from_email=app.config['SENDER_EMAIL'],
        to_emails=email,
        subject=subject,
        html_content=html_content
    )

    # Adicionar a imagem da logo como anexo
    with open('static/images/logo.png', 'rb') as img:
        img_data = img.read()
        encoded_img = base64.b64encode(img_data).decode()
        attachment = Attachment(
            file_content=FileContent(encoded_img),
            file_name=FileName('logo.png'),
            file_type=FileType('image/png'),
            disposition=Disposition('inline'),
            content_id='logo'
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
