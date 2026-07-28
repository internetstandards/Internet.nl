#!/usr/bin/env sh

scriptdir=$(dirname "$(readlink -f -- "$0")")
( \
  echo "# Docker container profiles overview\n\nThis overview was last generated with \`make update_container_documentation\`.\n\n"
  yq -r '"container|profiles|description","-|-|-",.services|to_entries|map([.key,(.value.profiles //[]|join(", "),(.key|head_comment|split("\n")|join("<br>")))]|join("|"))[]' $scriptdir/../docker/compose.yaml \
  | sed 's/$/|/' \
  | column -ts"|" -o" | " \
  | sed 's/^/| /;s/ $//;2{s/ /-/g}' \
) > $scriptdir/../documentation/Docker-container-profiles.md
