#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
project_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
workspace_dir=$(CDPATH= cd -- "$project_dir/.." && pwd)
image=certlab-gm-app:linux-amd64
cid=certlab-gm-export-$$

container build --arch amd64 \
  --build-arg VERSION=0.1.0-dev \
  --file "$project_dir/build/app/Containerfile" \
  --tag "$image" "$workspace_dir"

mkdir -p "$project_dir/dist"
container run --detach --name "$cid" --arch amd64 --rosetta "$image"
trap 'container delete "$cid" >/dev/null 2>&1 || true' EXIT HUP INT TERM
container cp "$cid:/certlab-gm" "$project_dir/dist/certlab-gm-linux-amd64"
chmod 0755 "$project_dir/dist/certlab-gm-linux-amd64"
shasum -a 256 "$project_dir/dist/certlab-gm-linux-amd64" > "$project_dir/dist/certlab-gm-linux-amd64.sha256"
