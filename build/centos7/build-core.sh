#!/bin/sh
set -eu

stage=/out/certarium-nginx-interop
nginx_src=/work/nginx
tongsuo_src=/work/tongsuo
pcre2_src=/work/pcre2

rm -rf "$stage"
mkdir -p "$stage/bin" "$stage/conf" "$stage/html" "$stage/licenses"

cd "$nginx_src"
git reset --hard HEAD
git apply --check /work/ntls.patch
git apply /work/ntls.patch

auto/configure \
  --prefix=/opt/certarium/examples/nginx \
  --sbin-path=/opt/certarium/examples/nginx/sbin/nginx \
  --conf-path=/opt/certarium/examples/nginx/conf/nginx.conf \
  --pid-path=/run/certarium-nginx-example.pid \
  --error-log-path=/var/log/certarium/nginx-example-error.log \
  --http-log-path=/var/log/certarium/nginx-example-access.log \
  --with-http_ssl_module \
  --with-http_stub_status_module \
  --with-openssl="$tongsuo_src" \
  --with-openssl-opt='enable-ntls no-tests' \
  --with-pcre="$pcre2_src" \
  --add-module=/work/ngx_tongsuo_ntls \
  --without-http_gzip_module \
  --without-http_auth_basic_module

if ! make -j"$(getconf _NPROCESSORS_ONLN)" > /out/build.log 2>&1; then
  echo 'Nginx/Tongsuo build failed; final 200 log lines follow:' >&2
  tail -n 200 /out/build.log >&2
  exit 1
fi

cp objs/nginx "$stage/bin/nginx"
cp conf/mime.types "$stage/conf/mime.types"
cp docs/html/index.html "$stage/html/index.html"
cp LICENSE "$stage/licenses/nginx-LICENSE"
cp "$tongsuo_src/LICENSE.txt" "$stage/licenses/tongsuo-LICENSE.txt"
cp "$pcre2_src/LICENCE.md" "$stage/licenses/pcre2-LICENCE.md"

{
  echo 'Certarium Nginx/TLCP interoperability build manifest'
  echo "built_at_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "build_arch=$(uname -m)"
  echo "glibc=$(getconf GNU_LIBC_VERSION)"
  echo "gcc=$(gcc -dumpfullversion -dumpversion 2>/dev/null || gcc -dumpversion)"
  echo "nginx_commit=$(cd "$nginx_src" && git rev-parse HEAD)"
  echo "tongsuo_commit=$(cd "$tongsuo_src" && git rev-parse HEAD)"
  echo "pcre2_tag=$(cd "$pcre2_src" && git describe --tags --exact-match)"
  echo
  "$stage/bin/nginx" -V 2>&1
} > "$stage/BUILD-MANIFEST.txt"

ldd "$stage/bin/nginx" > "$stage/LDD.txt"
readelf --version-info "$stage/bin/nginx" > "$stage/GLIBC-VERSIONS.txt"
strings "$stage/bin/nginx" \
  | grep -E 'enable_ntls|ssl_sign_certificate|ssl_enc_certificate|SSL_CTX_enable_ntls' \
  | sort -u > "$stage/NTLS-SYMBOLS.txt"

test -s "$stage/NTLS-SYMBOLS.txt"
test "$(uname -m)" = x86_64

(cd /out && tar -czf certarium-nginx-interop-linux-amd64.tar.gz certarium-nginx-interop)
(cd /out && sha256sum certarium-nginx-interop-linux-amd64.tar.gz > SHA256SUMS)
