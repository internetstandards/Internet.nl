# Copyright: 2019, NLnet Labs and the Internet.nl contributors
# SPDX-License-Identifier: Apache-2.0
import os

from celery import Celery

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'internetnl.settings')

app = Celery('internetnl')

app.config_from_object('django.conf:settings')

app.autodiscover_tasks()

# https://github.com/celery/celery/issues/4105
app.backend.result_consumer.start("")


@app.task(bind=True)
def debug_task(self):
    print('Request: {0!r}'.format(self.request))
