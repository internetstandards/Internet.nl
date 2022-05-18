from django.core.management.base import BaseCommand
from django.db import connection

from interface.batch import BATCH_INDEXES


class Command(BaseCommand):
    help = "Creates the DB indexes needed for the batch API."

    def info(self, text):
        if self.v_level:
            self.stdout.write(f"{text}")

    def debug(self, text):
        if self.v_level > 1:
            self.stdout.write(f"{text}")

    def create_index(self, table, index_field, index_name):
        self.info(f"* Creating index ({index_name}) on {table} for {index_field}")
        with connection.cursor() as cursor:
            sql = f"DROP INDEX IF EXISTS {index_name}"
            self.debug(sql)
            cursor.execute(sql)
            sql = f"CREATE INDEX {index_name} on {table} ({index_field})"
            self.debug(sql)
            cursor.execute(sql)

    def handle(self, *args, **options):
        self.v_level = options["verbosity"]
        self.info("Creating indexes...\n")
        for table, index_field, index_name in BATCH_INDEXES:
            self.create_index(table, index_field, index_name)
        self.info("Done!")
