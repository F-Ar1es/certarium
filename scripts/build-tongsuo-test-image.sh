#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
project_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
. "$project_dir/VERSIONS.env"

container build \
  --build-arg "TONGSUO_COMMIT=$TONGSUO_COMMIT" \
  --file "$project_dir/build/tongsuo-test/Containerfile" \
  --tag certarium-tongsuo-test:8.4.0 \
  "$project_dir"
