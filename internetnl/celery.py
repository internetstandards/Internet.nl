# Copyright: 2019, NLnet Labs and the Internet.nl contributors
# SPDX-License-Identifier: Apache-2.0
import os

from celery import Celery
from celery.schedules import crontab

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'internetnl.settings')

app = Celery('internetnl')

app.config_from_object('django.conf:settings', namespace='CELERY')

app.autodiscover_tasks()

@app.task(bind=True)
def debug_task(self):
    print('Request: {0!r}'.format(self.request))

if app.conf.ENABLE_BATCH:
    app.conf.beat_schedule = {
        'run_batch': {
                'task': 'checks.batch.scheduler.run',
                'schedule': app.conf.BATCH_SCHEDULER_INTERVAL
        }
    }
else:
    # Disable HoF when on batch mode, too much DB activity.
    app.conf.beat_schedule = {
        'generate_HoF': {
                'task': 'checks.tasks.update.update_hof',
                'schedule': app.conf.HOF_UPDATE_INTERVAL
        }
    }
