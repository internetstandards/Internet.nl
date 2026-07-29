#!/usr/bin/env sh
set -u

if [ $# -eq 0 ]; then
  >&2 echo "Please provide an argument: The root anchor key file, that is read in and written out."
  exit 1
fi

/opt/unbound/sbin/unbound-anchor -a "$1"
# The following sed rules do:
# s/ *;;.*//g				remove all metadata comments
# s/^(.\t)[0-9]+\t/\1/g		remove all TTLs
# /^$/d						delete empty lines
sed -ri 's/ *;;.*//g;s/^(.\t)[0-9]+\t/\1/g;/^$/d' "$1"
# use C to have binary order and reverse to put ; above .
LC_ALL=C sort -ro "$1" "$1"
