#!/usr/bin/env bash
set -e
cd tmp
tar -czf content_repo.tar.gz locale_files/*
cd ..
python3 bin/pofiles.py from_tar tmp/content_repo.tar.gz

# to_django is performed in Dockerfile

# list translation problems in the imported content, without failing the import
SKIP_SECRET_KEY_CHECK=1 CACHE_LOCATION= python3 manage.py check_translations || true
