#!/bin/env sh

( \
  echo "# Docker container profiles overview\n\nThis overview was last generated at $(date -uIseconds|sed 's/+00:00/Z/g') with \`make update_container_documentation\`.\n\n"
  docker run --rm --security-opt=no-new-privileges --cap-drop all --network none -v "$PWD/docker/compose.yaml":"/docker/compose.yaml" \
  mikefarah/yq:4.45.1 -r '"container|profiles|description","-|-|-",.services|to_entries|map([.key,(.value.profiles //[]|join(", "),(.key|head_comment|split("\n")|join("<br>")))]|join("|"))[]' /docker/compose.yaml \
  | sed 's/$/|/' \
  | column -ts"|" -o" | " \
  | sed 's/^/| /;s/ $//;2{s/ /-/g}' \
) > documentation/Docker-container-profiles.md
