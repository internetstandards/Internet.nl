#!/usr/bin/env bash
cd tmp
tar -czf content_repo.tar.gz locale_files/*
cd ..
python3 bin/pofiles.py from_tar tmp/content_repo.tar.gz

# to_django is performed in Dockerfile