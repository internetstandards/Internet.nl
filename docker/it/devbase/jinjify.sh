#!/bin/bash
# Expands {{ENV_VAR}} references into the value of ENV_VAR.
set -e -u

RED='\033[0;31m'
NOCOLOUR='\033[0m'

my_abort() {
    echo >&2 $*
    exit 2
}

[ $# -ge 1 ] || my_abort "Usage: $0 <path/to/directory/to/jinjify>"
which j2 >/dev/null || my_abort "Please install j2cli using: pip install j2cli"

# expands Jinja2 template references in every file in the given directory
# see: https://unix.stackexchange.com/a/139369 for an explanation about the glob usage
# use 'j2cli' instead of 'envsubst' because zone files can contain $directives which envsubst incorrectly replaces.
# pipe pushd/popd stdout and stderr to /dev/null to avoid their noisy unnecessary output

# for every file or every file in the directories specified by the given arguments
while [ $# -gt 0 ]; do
    echo "Jinja2: Processing $1.."
    if [ -f $1 ]; then
        INPUT_SET=$1
        MUST_POP=0
    else
        MUST_POP=1
        pushd $1 &>/dev/null
        shopt -s globstar dotglob
        INPUT_SET=**/*
    fi

    for f in ${INPUT_SET}; do
        [ -f $f ] || continue         # only process files
        echo -n "Jinja2: .. $f: "
        mv $f $f.bak                  # backup the original file
        j2 $f.bak > $f                # expand Jinja2 template language fragments
        cmp -s $f.bak $f && rm $f.bak # discard the backup if the file is unmodified
        if [ -e $f.bak ]; then
          echo -e "${RED}Processed${NOCOLOUR}"
        else
          echo "Unmodified"
        fi
    done
    [ ${MUST_POP} -eq 1 ] && popd &>/dev/null
    shift
done

echo "Jinja2: Processing complete"
