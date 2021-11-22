from django.core.management.base import BaseCommand
from internetnl.celery import debug_task


class Command(BaseCommand):
    help = 'Create a debug task to verify tasks are submitted to celery and the right worker.'

    def handle(self, *args, **options):
        debug_task.apply_async()
