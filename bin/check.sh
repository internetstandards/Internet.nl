#!/usr/bin/env bash

# runs checks that are not covered by linting or (unit)testing

fail=0

requirements_files="requirements.in requirements-dev.in"
echo $requirements_files | xargs -n1 pip-compile --quiet
if [ ! -z "$(git status --porcelain $requirements_files)" ];then
  echo "Requirements .in files have not all been compiled into .txt files and commited to Git!"
  git status --porcelain $requirements_files
  fail=1
fi

# verify DEBUG can only be enabled when authentication is set (should exit 1 and print error message)
command="docker run -ti --rm -e DEBUG=True -e AUTH_ALL_URLS -e ALLOW_LIST ghcr.io/internetstandards/webserver"
output=$($command)
exit_code=$?
if [ $exit_code -ne 1 ];then
  echo "$command"
  echo "exit code: $?"
  echo "output: $output"
  echo
  echo "Webserver should fail with exit code 1 if authentication/allowlist is not set when DEBUG=True"
  fail=1
fi

exit "$fail"
