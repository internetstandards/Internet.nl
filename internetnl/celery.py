# Copyright: 2022, ECP, NLnet Labs and the Internet.nl contributors
# SPDX-License-Identifier: Apache-2.0
import os
import time

from celery import Celery
from django.utils.autoreload import autoreload_started
from django.dispatch import receiver


os.environ.setdefault("DJANGO_SETTINGS_MODULE", "internetnl.settings")

app = Celery("internetnl")

app.config_from_object("django.conf:settings", namespace="CELERY")

app.autodiscover_tasks()


@app.task(bind=True)
def debug_task(self):
    print(f"Debug Task. Request: {self.request!r}")
    return True


@app.task()
def waitsome(sleep):
    """Wait some time and return epoch at completion."""

    time.sleep(sleep)
    return time.time()


@app.task()
def dummy_task(number: int = 0):
    time.sleep(1)
    return number * number


if app.conf.ENABLE_BATCH:
    app.conf.beat_schedule["run_batch"] = {
        "task": "interface.batch.scheduler.run",
        "schedule": app.conf.BATCH_SCHEDULER_INTERVAL,
    }

if app.conf.ENABLE_HOF:
    # Disable HoF when on batch mode, too much DB activity.
    app.conf.beat_schedule["generate_HoF"] = {
        "task": "checks.tasks.update.update_hof",
        "schedule": app.conf.HOF_UPDATE_INTERVAL,
    }


@receiver(autoreload_started)
def restart_worker_on_autorestart(sender, **kwargs):
    """Send all worker shutdown signal so they will be restarted."""
    app.control.broadcast("shutdown")
