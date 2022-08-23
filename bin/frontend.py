# Copyright: 2022, ECP, NLnet Labs and the Internet.nl contributors
# SPDX-License-Identifier: Apache-2.0
from argparse import ArgumentParser
import io
import os
from uuid import uuid4 as uuid

import rjsmin
import sass


FRONTEND_FOLDER = "frontend"
FRONTEND_JS_FOLDER = "frontend/js"
FRONTEND_CSS_FOLDER = "frontend/css"

DJANGO_STATIC_FOLDER = "interface/static"
DJANGO_STATIC_JS_FOLDER = DJANGO_STATIC_FOLDER + "/js"
DJANGO_STATIC_CSS_FOLDER = DJANGO_STATIC_FOLDER + "/css"


def build_js(args=None):
    """
    Replace any hardcoded placeholders, minify JS and copy into Django's static
    folder.

    """
    print("-"*20)
    print("Building JS files.")
    unique = uuid().hex
    for root, dirs, files in os.walk(FRONTEND_JS_FOLDER):
        for filename in files:
            if filename.endswith(".js"):
                print("Found {}...".format(filename))
                content = ""
                filepath = os.path.join(root, filename)
                with io.open(filepath, "r", encoding="utf-8") as jsfile:
                    content = jsfile.read()

                content = content.replace("@@unique@@", unique)
                content_min = rjsmin.jsmin(content)
                filename, _ = filename.rsplit(".", 1)
                filepath = os.path.join(
                    DJANGO_STATIC_JS_FOLDER, filename + "-min.js")

                print("... minifying to {}".format(filepath))
                with io.open(filepath, 'w', encoding="utf-8") as f:
                    f.write(content_min)
        break
    print("Done!")


def build_css(args=None):
    """
    Build/minify CSS and copy into Django's static folder.

    """
    print("-"*20)
    print("Building CSS files.")
    for root, dirs, files in os.walk(FRONTEND_CSS_FOLDER):
        for filename in files:
            if filename.endswith(".css"):
                if filename == "style.css-notyet-scss":
                    continue
                print("Found {}...".format(filename))
                filepath = os.path.join(root, filename)
                content_min = sass.compile(
                    filename=filepath, output_style="compressed")
                filename, _ = filename.rsplit(".", 1)
                filepath = os.path.join(
                    DJANGO_STATIC_CSS_FOLDER, filename + "-min.css")
                print("... minifying to {}".format(filepath))
                with io.open(filepath, 'w', encoding="utf-8") as f:
                    f.write(content_min)
        break
    print("Done!")


def parse():
    """
    Parse the command line.

    Currently two subcommands are available:
    - css: compile any scss, minify css and copy into Django's static folder.
    - js: minify js and copy into Django's static folder.

    """
    parser = ArgumentParser()
    subparsers = parser.add_subparsers(
        title='subcommands', description='valid subcommands')

    parser.set_defaults(func=lambda x: parser.print_help())

    to_django = subparsers.add_parser('css')
    to_django.set_defaults(func=build_css)

    to_tar = subparsers.add_parser('js')
    to_tar.set_defaults(func=build_js)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    parse()
