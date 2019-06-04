#!/bin/bash
set -e -u

my_abort() {
    echo >&2 $*
    exit 2
}

echo "Jinja2: Processing $1"

[ $# -eq 1 ] || my_abort "Usage: $0 <path/to/directory/to/jinjify>"
which j2 || my_abort "Please install j2cli using: pip install j2cli"

# expands Jinja2 template references in every file in the given directory
# see: https://unix.stackexchange.com/a/139369 for an explanation about the glob usage
# use 'j2cli' instead of 'envsubst' because zone files can contain $directives which envsubst incorrectly replaces.
# pipe pushd/popd stdout and stderr to /dev/null to avoid their noisy unnecessary output

# for every file in the directory specified by the given argument
pushd $1 &>/dev/null
shopt -s globstar dotglob
for f in **/*; do
    [ -f $f ] || continue         # only process files
    echo -n "Jinja2: .. $f: "
    mv $f $f.bak                  # backup the original file
    j2 $f.bak > $f                # expand Jinja2 template language fragments
    cmp -s $f.bak $f && rm $f.bak # discard the backup if the file is unmodified
    if [ -e $f.bak ]; then
      echo "Processed"
    else
      echo "Unmodified"
    fi
done 
popd &>/dev/null

echo "Jinja2: Processing of $1 complete"