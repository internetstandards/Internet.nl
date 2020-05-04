from yaml import load, dump
try:
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
    from yaml import Loader, Dumper

from django.core.management.base import BaseCommand

from internetnl import batch_api_doc_conf as settings

OPENAPIFILE = "checks/batch/openapi.yaml"
DOC_DESTINATION = "documentation/openapi.yaml"
VALUES_MAP = {
    "TITLE": ['info', 'title'],
    "TERMS": ['info', 'termsOfService'],
    "CONTACT": ['info', 'contact'],
    "LOGO": ['info', 'x-logo'],
    "SERVERS": ['servers'],
}
REPLACE_MAP = {
    "DESC_INTRO_EXTRA": ['info', 'description'],
    "DESC_INTRO_REDOCLY_LINK": ['info', 'description'],
}


class Command(BaseCommand):
    help = (
        'Generate the batch API documentation based on configured values.')

    def add_arguments(self, parser):
        parser.add_argument(
            'ciphers', nargs='*',
            help='Zero or more OpenSSL cipher names to show details for.')

    def info(self, text):
        if self.v_level:
            self.stdout.write(f"{text}")

    def debug(self, text):
        if self.v_level > 1:
            self.stdout.write(f"{text}")

    def update_values(self, api_doc):
        self.info(f"Updating values...")
        for name, path in VALUES_MAP.items():
            self.debug(f"* Updating {' > '.join(path)}")
            current_node = api_doc
            for node in path[:-1]:
                current_node = current_node[node]
            current_node[path[-1]] = getattr(settings, name)

    def replace_text(self, api_doc):
        self.info(f"Replacing text...")
        for name, path in REPLACE_MAP.items():
            self.debug(f"* Replacing @@{name}@@ in {' > '.join(path)}")
            current_node = api_doc
            for node in path[:-1]:
                current_node = current_node[node]
            current_text = current_node[path[-1]]
            new_text = getattr(settings, name)
            current_node[path[-1]] = current_text.replace(
                f'@@{name}@@', new_text, 1)

    def handle(self, *args, **options):
        self.v_level = options['verbosity']
        self.info(f"Reading template file at {OPENAPIFILE}\n")
        with open(OPENAPIFILE, 'r') as f:
            api_doc = load(f, Loader=Loader)

        self.update_values(api_doc)
        self.replace_text(api_doc)

        with open(DOC_DESTINATION, 'w+') as f:
            dump(api_doc, f, Dumper=Dumper)

        self.stdout.write(f"Documentation file generated at {DOC_DESTINATION}")
