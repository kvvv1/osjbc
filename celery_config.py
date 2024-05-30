from celery import Celery
from celery.schedules import crontab

def make_celery(app):
    celery = Celery(
        app.import_name,
        broker=app.config['CELERY_BROKER_URL'],
        backend=app.config['CELERY_RESULT_BACKEND']  # Certifique-se de que a chave está correta
    )
    celery.conf.update(app.config)
    celery.conf.beat_schedule = {
        'send_reminders_every_day': {
            'task': 'tasks.send_reminders',
            'schedule': crontab(hour=0, minute=0),  # Executar todos os dias à meia-noite
        },
    }
    return celery
