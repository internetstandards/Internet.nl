# Copyright: 2026, ECP, NLnet Labs and the Internet.nl contributors
# SPDX-License-Identifier: Apache-2.0
"""
Check the translations against the code (#2145):
  * missing - keys the code translates, but that are not in the .po files (fails)
  * parity  - keys that only English or only Dutch has (fails)
  * broken  - translations that the translate tag cannot render, as they are not valid templates (fails)
  * gaps    - numbered keys that the numbered_keys tag counts, but that skip a number (fails)
  * unused  - keys that the code does not have in quotes anywhere (a warning, listed with -v 2)
"""

import re
from pathlib import Path

import polib
from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.template import Template, TemplateSyntaxError

TRANSLATIONS = Path(settings.BASE_DIR) / "translations"

# Keys built from runtime values, such as the texts of tests and verdicts, FAQ and article
# pages, and numbered template loops. The code scan cannot find these, so they never count as unused.
DYNAMIC_PREFIXES = (
    "about standards ",
    "article ",
    "author ",
    "detail ",
    "faqs ",
    "home why reason-",
    "manual halloffame ",
    "results no-icon-status ",
    "test ",
)

# This file is scanned too, so these comments have no examples with quotes.
# a key in single or double quotes
KEY = r"""["']([^"'\n]+)["']"""
# a quoted key in the translate or translate_attr tag, followed by the end of the tag or by as. When a
# filter follows the quoted string instead, as in the tag for test texts, it is only the start of a key.
TRANSLATE_TAG = re.compile(r"{%\s*translate(?:_attr)?\s+" + KEY + r"\s*(?:%}|as\s)")
# a quoted key given to _() in Python
GETTEXT = re.compile(r"\b_\(\s*" + KEY + r"\s*\)")
# a quoted pattern in the numbered_keys tag, which stops counting at the first number without a key
NUMBERED_KEYS = re.compile(r"{%\s*numbered_keys\s+" + KEY)


def msgids_from_po(locale, filename):
    return {entry.msgid for entry in polib.pofile(str(TRANSLATIONS / locale / filename)) if entry.msgid}


def python_or_html_files():
    base = Path(settings.BASE_DIR)
    yield from (base / "interface" / "templates").rglob("*.html")
    for directory in ("interface", "checks"):
        yield from (base / directory).rglob("*.py")


class Command(BaseCommand):
    help = "Check that the translations match the keys the code uses."

    def handle(self, *args, **options):
        code = "\n".join(path.read_text(encoding="utf-8") for path in python_or_html_files())
        defined = set().union(
            *(msgids_from_po("en", name) for name in ("main.po", "news.po", "manual_hof.po", "custom.po.dist"))
        )

        translated = set(TRANSLATE_TAG.findall(code)) | set(GETTEXT.findall(code))
        missing = sorted(translated - defined)

        # news.po is left out, as some articles only exist in Dutch
        parity = []
        for name in ("main.po", "manual_hof.po"):
            en, nl = msgids_from_po("en", name), msgids_from_po("nl", name)
            parity += [f"{name}: only in en: {key}" for key in sorted(en - nl)]
            parity += [f"{name}: only in nl: {key}" for key in sorted(nl - en)]

        broken = []
        for locale in ("en", "nl"):
            for name in ("main.po", "news.po", "manual_hof.po"):
                for entry in polib.pofile(str(TRANSLATIONS / locale / name)):
                    try:
                        Template(entry.msgstr)
                    except TemplateSyntaxError as error:
                        broken.append(f"{locale}/{name} {entry.msgid}: {error}")

        gaps = []
        for pattern in sorted(set(NUMBERED_KEYS.findall(code))):
            number = re.compile(re.escape(pattern).replace(r"\{\}", r"(\d+)"))
            numbers = sorted(int(match[1]) for key in defined if (match := number.fullmatch(key)))
            if numbers != list(range(1, len(numbers) + 1)):
                gaps.append(f"{pattern}: {numbers}")

        # Many keys reach the translate tag through a variable, such as the name given to content.html in an
        # include, or hof_text in a view. So any key the code has in quotes counts as used.
        unused = sorted(
            key
            for key in defined
            if not key.startswith(DYNAMIC_PREFIXES) and f'"{key}"' not in code and f"'{key}'" not in code
        )

        for title, lines in (
            ("Keys the code uses but that are missing from the .po files", missing),
            ("Keys that English and Dutch do not both have", parity),
            ("Translations that are not valid templates", broken),
            ("Numbered keys that skip a number, so the page stops before the gap", gaps),
        ):
            if lines:
                self.stdout.write(f"{title}:")
                for line in lines:
                    self.stdout.write(f"  {line}")
        if unused:
            self.stdout.write(f"{len(unused)} keys the code does not seem to use (a warning, -v 2 lists them)")
            if options["verbosity"] > 1:
                for key in unused:
                    self.stdout.write(f"  {key}")
        if missing or parity or broken or gaps:
            raise CommandError("translation checks failed, see above")
        self.stdout.write("Translations are consistent with the code.")
