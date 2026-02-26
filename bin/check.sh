#!/usr/bin/env bash

# runs checks that are not covered by linting or (unit)testing

fail=0

if ! uv lock --check &>/dev/null;then
  echo -e "\e[31mThe uv.lock file needs updating, please run 'make uv_lock' and commit the changes to Git!"
  uv lock --dry-run
  fail=1
fi

documentation_file="documentation/Docker-container-profiles.md"
bin/update_container_documentation.sh
if [ ! -z "$(git diff --word-diff=porcelain -G'^\| ' $documentation_file)" ];then
  echo -e "\e[31mThe docker container documentation is not up to date, please run 'make update_container_documentation' and commit the documentation to Git!"
  git diff --word-diff=porcelain -G'^\| ' $documentation_file
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
  echo -e "\e[31mWebserver should fail with exit code 1 if authentication/allowlist is not set when DEBUG=True"
  fail=1
fi

exit "$fail"
