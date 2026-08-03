#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
project_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
workspace_dir=$(CDPATH= cd -- "$project_dir/.." && pwd)

. "$project_dir/VERSIONS.env"

image=tlslab-core-builder:centos7-amd64
output_dir="$project_dir/.build/output"

test -f "$workspace_dir/nginx-gm-poc/patches/nginx-1.30.4-tongsuo-ntls.patch"
test -f "$workspace_dir/nginx-gm-poc/modules/ngx_tongsuo_ntls/config"

mkdir -p "$output_dir" "$project_dir/dist"

container build \
  --arch amd64 \
  --build-arg "NGINX_COMMIT=$NGINX_COMMIT" \
  --build-arg "TONGSUO_COMMIT=$TONGSUO_COMMIT" \
  --build-arg "PCRE2_VERSION=$PCRE2_VERSION" \
  --file "$project_dir/build/centos7/Containerfile" \
  --tag "$image" \
  "$workspace_dir"

container run \
  --arch amd64 \
  --rosetta \
  --rm \
  --volume "$output_dir:/out" \
  "$image"

cp "$output_dir/tlslab-core-linux-amd64.tar.gz" "$project_dir/dist/"
cp "$output_dir/SHA256SUMS" "$project_dir/dist/"

printf '%s\n' "Artifacts:" \
  "$project_dir/dist/tlslab-core-linux-amd64.tar.gz" \
  "$project_dir/dist/SHA256SUMS"

