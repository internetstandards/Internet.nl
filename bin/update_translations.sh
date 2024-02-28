#!/usr/bin/env bash
tar --strip-components=1 -cf tmp/content_repo.tar.gz locale_files/*
python3 bin/pofiles.py from_tar tmp/content_repo.tar.gz

# to_django is performed in Dockerfile