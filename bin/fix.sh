#!/usr/bin/env bash

set -x

# runs autoformat commands

autoflake -ri --remove-all-unused-imports ${@}
black --line-length 120 -q ${@}
/opt/frontend/node_modules/.bin/stylelint --config-basedir /opt/frontend --fix "frontend/src/**/*.css"
