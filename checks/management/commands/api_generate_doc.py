import os
import re
from yaml import load, dump
try:
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
    from yaml import Loader, Dumper

from django.core.management.base import BaseCommand
from django.conf import settings

from internetnl import batch_api_doc_conf as batch_settings
from checks.batch.custom_results import CUSTOM_RESULTS_MAP
from checks import models

OPENAPIFILE = "checks/batch/openapi.yaml"
DOC_DESTINATION = os.path.join(settings.STATIC_ROOT, "openapi.yaml")
VALUES_MAP = {
    "TITLE": ['info', 'title'],
    "TERMS": ['info', 'termsOfService'],
    "CONTACT": ['info', 'contact'],
    "LOGO": ['info', 'x-logo'],
    "SERVERS": ['servers'],
    "BATCH_API_FULL_VERSION": ['info', 'version']
}
REPLACE_MAP = {
    "DESC_INTRO_EXTRA": ['info', 'description'],
    "DESC_INTRO_REDOCLY_LINK": ['info', 'description'],
}
TECHNICAL_RESULTS_ENUMCLASS = [
    ['components', 'schemas', 'TechnicalSharedDetails', 'properties'],
    ['components', 'schemas', 'TechnicalWebServerDetails', 'properties'],
    ['components', 'schemas', 'TechnicalReceivingMailServerDetails', 'properties'],
    ['components', 'schemas', 'DomainMailTechnical', 'properties', 'domain', 'properties', 'dmarc', 'properties'],
    ['components', 'schemas', 'DomainMailTechnical', 'properties', 'domain', 'properties', 'spf', 'properties'],
]

ENUM_DESCRIPTION_REGEX = re.compile(r"\* `([^`]+)` -")


class Command(BaseCommand):
    help = (
        'Generate the batch API documentation also based on configured '
        'values.')

    def info(self, text):
        if self.v_level:
            self.stdout.write(f"{text}")

    def debug(self, text):
        if self.v_level > 1:
            self.stdout.write(f"{text}")

    def update_values(self, api_doc):
        """
        Updates strutures in the API text with configured values.

        """
        self.info(f"Updating values...")
        for name, path in VALUES_MAP.items():
            self.debug(f"* Updating {'.'.join(path)}")
            current_node = api_doc
            for node in path[:-1]:
                current_node = current_node[node]
            current_node[path[-1]] = getattr(batch_settings, name)

    def replace_text(self, api_doc):
        """
        Replaces API text with configured values.

        """
        self.info(f"Replacing text...")
        for name, path in REPLACE_MAP.items():
            self.debug(f"* Replacing @@{name}@@ in {'.'.join(path)}")
            current_node = api_doc
            for node in path[:-1]:
                current_node = current_node[node]
            current_text = current_node[path[-1]]
            new_text = getattr(batch_settings, name)
            current_node[path[-1]] = current_text.replace(
                f'@@{name}@@', new_text, 1)

    def add_custom_results(self, api_doc):
        """
        Adds the available custom results to the API document.

        """
        results_schema = api_doc['components']['schemas']['CustomResults']
        required = []
        properties = {}
        results_schema['required'] = required
        results_schema['properties'] = properties
        for custom in (
                CUSTOM_RESULTS_MAP[r] for r, active
                in settings.BATCH_API_CUSTOM_RESULTS.items() if active):
            if custom.required:
                required.append(custom.name)
            properties[custom.name] = custom.openapi_spec

    def complete_technical_results(self, api_doc):
        """
        Completes the technical results specification by adding the `enum`
        specifications for the data in the results_technical endpoint. It also
        checks that all these fields are covered in the description.

        """
        self.info("Completing technical results...")
        for path in TECHNICAL_RESULTS_ENUMCLASS:
            current_node = api_doc
            for node in path[:-1]:
                current_node = current_node[node]
            last_node = current_node[path[-1]]
            for key, value in last_node.items():
                if 'enumClass' not in value:
                    continue
                self.debug(f"* Updating and checking {key} in {'.'.join(path)}")
                cls = getattr(models, value['enumClass'])
                members = set(cls.__members__)
                value['enum'] = [m for m in members]
                documented_members = set(ENUM_DESCRIPTION_REGEX.findall(value['description']))
                undocumented = members - documented_members
                unspecified = documented_members - members
                if undocumented:
                    raise Exception(f"Found undocumented members: {undocumented}")
                if unspecified:
                    raise Exception(f"Found unspecified members: {unspecified}")
                del value['enumClass']

    def handle(self, *args, **options):
        self.v_level = options['verbosity']
        self.info(f"Reading template file at {OPENAPIFILE}\n")
        with open(OPENAPIFILE, 'r') as f:
            api_doc = load(f, Loader=Loader)

        self.update_values(api_doc)
        self.replace_text(api_doc)
        self.add_custom_results(api_doc)
        self.complete_technical_results(api_doc)
        del api_doc['DISCLAIMER']

        with open(DOC_DESTINATION, 'w+') as f:
            dump(api_doc, f, Dumper=Dumper)

        self.stdout.write(f"Documentation file generated at {DOC_DESTINATION}")
