# Copyright: 2022, ECP, NLnet Labs and the Internet.nl contributors
# SPDX-License-Identifier: Apache-2.0
import markdown
import io
import os
import sys
import shutil
from collections import defaultdict
from datetime import datetime
from argparse import ArgumentParser

import polib

if sys.version_info[0] == 2:
    import pathlib2 as pathlib
    import string
    from subprocess import call as run
else:
    import pathlib
    string = str
    from subprocess import run

KNOWN_PO_FILES = [
    ("main.po", []),
    ("news.po", ['article', 'author']),
    ("manual_hof.po", ['manual halloffame']),
]
PO_FILES_DIR = "translations"
PO_FILES_LOCALES = PO_FILES_DIR + "/{}"

DJANGO_PO_FILE = "locale/{}/LC_MESSAGES/django.po"
DJANGO_ASSETS_DIR = "assets/"

TAR_UNPACK_DIR = "locale_files"
TAR_NAME = TAR_UNPACK_DIR + ".tar.gz"
TAR_DEST_DIR = "/tmp"
TAR_DEST_PATH = TAR_DEST_DIR + "/" + TAR_NAME


def get_locales():
    locales = next(os.walk(PO_FILES_DIR))[1]
    print(f'Found locales: {locales}')
    return locales


def get_translation_filenames():
    return [x[0] for x in KNOWN_PO_FILES]


def merge(this_po, that_po, replace_duplicates=False):
    """
    Merge two pofiles.

    If `replace_duplicates` is set and there duplicate entries replace this
    with that.

    """
    merged = this_po
    for entry in that_po:
        try:
            merged.append(entry)
        except ValueError:
            if not replace_duplicates:
                raise ValueError(
                    f"Found duplicate entry: '{entry.msgid}'")
            this_entry = merged.find(
                entry.msgid, include_obsolete_entries=True)
            this_entry.msgstr = entry.msgstr
    return merged


def print_status(filename, po_file):
    """
    Print the status of the po_file.

    """
    print(f"{filename}")
    print(f'translated entries: {len(po_file.translated_entries())}')
    print('non translated entries: {}'.format(
        len(po_file.untranslated_entries())))
    print("")


def copytree(this, that):
    """
    Copy the directory structure of this into that.

    """
    for root, _, files in os.walk(this):
        root_to = root.replace(this, that, 1)
        pathlib.Path(root_to).mkdir(parents=True, exist_ok=True)
        for f in files:
            filepath_from = os.path.join(root, f)
            filepath_to = os.path.join(root_to, f)
            shutil.copy2(filepath_from, filepath_to)


def read_translations():
    """
    Read the translation files and return a dict with the contents.

    """
    locales = get_locales()
    po_files = {locale: dict() for locale in locales}

    for locale in locales:
        print("-"*20)
        print(f"Locale: {locale}\n")
        available_files = get_translation_filenames()

        try:
            filename = "main.po"
            available_files.remove("main.po")
            filepath = "{}/{}".format(
                PO_FILES_LOCALES.format(locale), filename)
            if not os.path.isfile(filepath):
                raise ValueError
        except ValueError:
            print(
                "Could not find main.po in '{}' locale, aborting!"
                "".format(locale))

        po_files[locale][filename] = polib.pofile(
            filepath, check_for_duplicates=True)
        now = datetime.now().isoformat(' ')
        po_files[locale][filename].metadata['PO-Revision-Date'] = now
        print_status(filename, po_files[locale][filename])

        for filename in available_files:
            filepath = "{}/{}".format(
                PO_FILES_LOCALES.format(locale), filename)
            if os.path.isfile(filepath):
                po_file = polib.pofile(filepath, check_for_duplicates=True)
                print_status(filename, po_file)
                po_files[locale][filename] = po_file

    print("-"*20)
    return po_files


def build_django_files(args=None):
    """
    Build the django po files from the translations.

    """
    print("Building Django .po files from translations...")
    translations = read_translations()
    for locale in translations:
        merged_po = translations[locale]["main.po"]
        filenames = list(translations[locale].keys())
        filenames.remove("main.po")
        for filename in filenames:
            po_file = translations[locale][filename]
            try:
                merged_po = merge(merged_po, po_file)
            except ValueError as e:
                print(f"{e} in {locale}/{filename}. Aborting...")
                return
        merged_po.sort()
        print(f"Converting '{locale}' locale to markdown...")
        for entry in merged_po:
            if entry.msgstr in ["", " "]:
                entry.msgstr = " "
                continue

            md = markdown.markdown(entry.msgstr)
            # Markdown also translates simple text to:
            # <p>text</p>
            # Remove the <p> tag for these cases.
            if (md.startswith("<p>") and md.endswith("</p>")
                    and md[3:].find("<p>") == -1):
                md = md.split("<p>", 1)[1].rsplit("</p>", 1)[0]
            entry.msgstr = md

        print(f"Writing '{locale}' locale...")
        filename = DJANGO_PO_FILE.format(locale)
        os.makedirs(filename.rsplit('/', 1)[0], exist_ok=True)
        merged_po.save(filename)
    print("Done!")


def build_tar(args=None):
    """
    Explode the translation po files to a directory structure, build the tar
    file, zip it and place it in an accessible directory.

    """
    print("Removing previous directory structure...")
    try:
        shutil.rmtree(TAR_UNPACK_DIR)
    except FileNotFoundError:
        pass
    pathlib.Path(TAR_UNPACK_DIR).mkdir(parents=True, exist_ok=True)

    print("Building tar from translations...")
    translations = read_translations()
    for locale, po_files in translations.items():
        for filename, po_file in po_files.items():
            for entry in po_file:
                if entry.msgid == "":
                    continue
                mapping = string.maketrans(" \t\n", "///")
                filename = string.translate(str(entry.msgid), mapping)
                filename = filename + "_" + locale + ".md"
                folder, filename = filename.rsplit("/", 1)
                folder = TAR_UNPACK_DIR + "/" + folder
                pathlib.Path(folder).mkdir(parents=True, exist_ok=True)
                filepath = folder + "/" + filename
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(entry.msgstr)
                    f.write("\n")

    print("Copying the assets...")
    copytree(DJANGO_ASSETS_DIR, TAR_UNPACK_DIR)

    print("Creating and compressing the tar...")
    run(["tar", "-zcf", TAR_DEST_PATH, TAR_UNPACK_DIR])

    print(f"Done!\nThe tar is available at '{TAR_DEST_PATH}'.")


def read_tar(args):
    """
    Read the (compressed) tar and update the translation files.

    """
    print(f"Reading {args.tar_file} into translations...")
    if not os.path.isfile(args.tar_file):
        print(f"{args.tar_file} is not a file! Aborting...")
        return

    print("Removing previous directory structure...")
    try:
        shutil.rmtree(TAR_UNPACK_DIR)
    except FileNotFoundError:
        pass

    print("Decompressing the tar...")
    run(["tar", "-zxvf", args.tar_file])

    translations = read_translations()

    # The following generates the dict:
    #   read_po_files[locale][filename]
    # where:
    #   - locale is the locale
    #   - filename is main.po, news.po, etc
    read_po_files = defaultdict(lambda: defaultdict(polib.POFile))

    locales = {locale for locale in translations}
    assets = []
    print(f"Going to walk over files in {TAR_UNPACK_DIR}.")
    for root, _, files in os.walk(TAR_UNPACK_DIR):
        print(f"Walking over files: {files}")
        msgid_start = root.replace(TAR_UNPACK_DIR + "/", "").replace("/", " ")
        for filename in files:
            filepath = os.path.join(root, filename)
            if filename.endswith(".md"):
                filename, _ = filename.rsplit(".", 1)
                msgid, locale = filename.rsplit("_", 1)
                msgid = f"{msgid_start} {msgid}"
                with open(filepath, encoding='utf-8') as f:
                    content = f.read().strip("\n")
                po_entry = polib.POEntry(msgid=msgid, msgstr=content)

                # Check in which file we should save the POEntry
                target_filename = None
                for filename, known_strings in KNOWN_PO_FILES:
                    if not known_strings:
                        target_filename = filename
                    else:
                        for known_string in known_strings:
                            if po_entry.msgid.startswith(known_string):
                                target_filename = filename

                print(f"Adding {target_filename} to {locale} with entry: {po_entry}.")
                read_po_files[locale][target_filename].append(po_entry)

                locales.add(locale)
            else:
                assets.append(filepath)

    for locale, po_files in translations.items():
        locales.discard(locale)
        for filename in po_files.keys():
            po_files[filename] = merge(
                po_files[filename], read_po_files[locale][filename],
                replace_duplicates=True)

    # New locales from tar
    for locale in locales:
        print(f"New locale: '{locale}'")
        translations[locale] = {}
        for filename, po_file in read_po_files[locale].items():
            translations[locale][filename] = polib.POFile()
            translations[locale][filename] = merge(
                translations[locale][filename], po_file,
                replace_duplicates=True)

    for locale, po_files in translations.items():
        for filename, po_file in po_files.items():
            po_file.sort()
            directory = PO_FILES_LOCALES.format(locale)
            filepath = directory + "/" + filename
            print(f"Writing {filepath}")
            pathlib.Path(directory).mkdir(parents=True, exist_ok=True)
            po_file.save(filepath)

    print("Copying assets...")
    for asset_from in assets:
        asset_to = asset_from.replace(TAR_UNPACK_DIR, "", 1)
        asset_to = DJANGO_ASSETS_DIR + asset_to
        dir_to, _ = asset_to.rsplit("/", 1)
        pathlib.Path(dir_to).mkdir(parents=True, exist_ok=True)
        shutil.copy2(asset_from, asset_to)

    print("Done!")


def parse():
    """
    Parse the command line.

    Currently three subcommands are available:
    - to_django: combine translations to django PO files.
    - to_tar: explode PO files to a directory structure and tar it.
    - from_tar: update the translations from the tar.

    """
    parser = ArgumentParser()
    subparsers = parser.add_subparsers(
        title='subcommands', description='valid subcommands')

    parser.set_defaults(func=lambda x: parser.print_help())

    to_django = subparsers.add_parser('to_django')
    to_django.set_defaults(func=build_django_files)

    to_tar = subparsers.add_parser('to_tar')
    to_tar.set_defaults(func=build_tar)

    from_tar = subparsers.add_parser('from_tar')
    from_tar.add_argument('tar_file', help="the tar file")
    from_tar.set_defaults(func=read_tar)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    parse()
