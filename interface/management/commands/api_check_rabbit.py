from django.conf import settings
from django.core.management.base import BaseCommand

from interface.batch.scheduler import Rabbit


class Command(BaseCommand):
    help = "Attempt to connect to RabbitMQ, as a worker would do."

    def handle(self, *args, **options):
        print(f"Creating client to: RABBIT:{settings.RABBIT} USER: {settings.RABBIT_USER}.")
        client = Rabbit(settings.RABBIT, settings.RABBIT_USER, settings.RABBIT_PASS)
        print(f"Retrieving load: RABBIT_VHOST:{settings.RABBIT_VHOST} RABBIT_MON_QUEUE: {settings.RABBIT_MON_QUEUE}.")
        current_load = client.get_queue_depth(settings.RABBIT_VHOST, settings.RABBIT_MON_QUEUE)
        print(f"Current Load: {current_load}.")
        print("Done.")
