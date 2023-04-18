#!/bin/sh

chown nobody:nogroup /app/batch_results
echo "$@"
exec runuser --user=nobody -- "$@"