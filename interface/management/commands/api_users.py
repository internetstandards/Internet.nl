from enum import Enum, auto
import json

from django.core.management.base import BaseCommand, CommandParser
from django.core.management.base import CommandError
from django.db import transaction

from interface.batch.util import create_batch_user
from interface.models import BatchUser


class FormatType(Enum):
    cli = auto()
    csv = auto()
    json = auto()


class Command(BaseCommand):
    help = 'Creates an API user in the database.'

    def info(self, text):
        if self.v_level:
            self.stdout.write(f"{text}")

    def debug(self, text):
        if self.v_level > 1:
            self.stdout.write(f"{text}")

    def output_cli(self, headers, users):
        res = [headers] + users
        max_length = [0 for i in range(len(res[0]))]
        for i in range(len(max_length)):
            max_length[i] = max(map(lambda x: len(x[i]), res))
        for s in res:
            lines = [
                '{:<{}}'.format(x, max_length[i])
                for i, x in enumerate(s)
            ]
            self.info(' '.join(lines))

    def output_csv(self, headers, users):
        res = [headers] + users
        for s in res:
            self.info(','.join(s))

    def output_json(self, headers, users):
        res = []
        for user in users:
            res.append({
                headers[i].lower(): x
                for i, x in enumerate(user)
            })
        self.info(json.dumps(res))

    def list_users(self):
        users = [
            (f'{u.id}', u.username, u.name, u.organization, u.email)
            for u in BatchUser.objects.order_by('id').all()
        ]
        if not users:
            raise CommandError("No registered API users.")
        headers = ('ID', 'Username', 'Name', 'Organization', 'Email')
        if self.format == FormatType.cli.name:
            self.output_cli(headers, users)
        elif self.format == FormatType.csv.name:
            self.output_csv(headers, users)
        elif self.format == FormatType.json.name:
            self.output_json(headers, users)

    def register_user(self):
        try:
            BatchUser.objects.get(username=self.username)
            raise CommandError(
                f"The user '{self.username}' already exists. Try "
                f"`api_users update` instead.")
        except BatchUser.DoesNotExist:
            create_batch_user(
                self.username, self.name, self.organization, self.email)

    def update_user(self):
        try:
            user = BatchUser.objects.get(username=self.username)
            user.name = self.name
            user.organization = self.organization
            user.email = self.email
            user.save()
        except BatchUser.DoesNotExist:
            raise CommandError(
                f"The user '{self.username}' does not exist. Try "
                f"`api_users register` instead.")

    @transaction.atomic
    def remove_user(self):
        try:
            user = BatchUser.objects.get(username=self.username)
            if not self.yes:
                cont = False
                res = input(
                    f"This will delete user {self.username} along with all "
                    f"the submitted batch requests, batch results and "
                    f"generated reports.\n"
                    f"Do you want to continue? [y/N]\n")
                if res.lower() == "y":
                    cont = True
                if not cont:
                    return
            user.delete_related_data(delete_self=True)

        except BatchUser.DoesNotExist:
            raise CommandError(
                f"The user '{self.username}' does not exist.")

    def add_arguments(self, parser):
        cmd = self
        subparsers = parser.add_subparsers(
            title='sub-commands', description='Available sub-commands',
            dest='sub-command', required=True)

        list_parser = subparsers.add_parser(
            'list', help='List the registered API users')
        list_parser.add_argument(
            '-f', '--format', default=FormatType.cli.name,
            choices=[
                FormatType.cli.name, FormatType.csv.name,
                FormatType.json.name])
        list_parser.set_defaults(func=self.list_users)

        register_parser = subparsers.add_parser(
            'register', help='Register a new API user')
        register_parser.set_defaults(func=self.register_user)
        register_parser.add_argument('-u', '--username', required=True)
        register_parser.add_argument('-n', '--name', required=True)
        register_parser.add_argument('-o', '--organization', required=True)
        register_parser.add_argument('-e', '--email', required=True)

        update_parser = subparsers.add_parser(
            'update', help='Update an existing API user')
        update_parser.set_defaults(func=self.update_user)
        update_parser.add_argument('-u', '--username', required=True)
        update_parser.add_argument('-n', '--name', required=True)
        update_parser.add_argument('-o', '--organization', required=True)
        update_parser.add_argument('-e', '--email', required=True)

        remove_parser = subparsers.add_parser(
            'remove', help='Remove an existing API user')
        remove_parser.set_defaults(func=self.remove_user)
        remove_parser.add_argument('-u', '--username', required=True)
        remove_parser.add_argument(
            '-y', '--yes', action='store_true',
            help="Assume yes to removal prompt")

    def handle(self, *args, **options):
        self.v_level = options['verbosity']
        self.format = options.get('format')
        self.username = options.get('username')
        self.name = options.get('name')
        self.organization = options.get('organization')
        self.email = options.get('email')
        self.yes = options.get('yes')
        options['func']()
