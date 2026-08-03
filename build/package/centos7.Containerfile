FROM docker.io/library/golang:1.22-bookworm AS app
ARG VERSION
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go test ./... \
 && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath \
      -ldflags "-s -w -X main.version=${VERSION}" -o /certarium ./cmd/certarium \
 && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath \
      -ldflags "-s -w -X main.version=${VERSION}" -o /certarium-backup ./cmd/certarium-backup

FROM docker.io/library/debian:12-slim AS source
ARG TONGSUO_COMMIT
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates git \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /source
RUN git clone https://github.com/Tongsuo-Project/Tongsuo.git \
 && cd Tongsuo \
 && git checkout --detach "${TONGSUO_COMMIT}" \
 && test "$(git rev-parse HEAD)" = "${TONGSUO_COMMIT}"

FROM quay.io/centos/centos:7
ARG TONGSUO_COMMIT
ENV TONGSUO_COMMIT=${TONGSUO_COMMIT}
RUN printf '%s\n' \
      '[base]' 'name=CentOS-7 - Base' 'baseurl=http://archive.kernel.org/centos-vault/7.9.2009/os/$basearch/' 'enabled=1' 'gpgcheck=0' \
      '[updates]' 'name=CentOS-7 - Updates' 'baseurl=http://archive.kernel.org/centos-vault/7.9.2009/updates/$basearch/' 'enabled=1' 'gpgcheck=0' \
      '[extras]' 'name=CentOS-7 - Extras' 'baseurl=http://archive.kernel.org/centos-vault/7.9.2009/extras/$basearch/' 'enabled=1' 'gpgcheck=0' \
      > /etc/yum.repos.d/CentOS-Base.repo \
 && yum -y install ca-certificates file gcc make perl perl-Data-Dumper perl-IPC-Cmd rpm-build tar which \
 && yum clean all && rm -rf /var/cache/yum
WORKDIR /build
COPY --from=source /source/Tongsuo /build/Tongsuo
RUN cd Tongsuo \
 && ./config --prefix=/opt/tongsuo no-shared no-tests enable-ntls \
 && make -j2 build_sw \
 && make install_sw
COPY --from=app /certarium /build/certarium
COPY --from=app /certarium-backup /build/certarium-backup
COPY packaging /src/packaging
COPY LICENSE NOTICE THIRD_PARTY_NOTICES.md COMMERCIAL_LICENSE.md /src/
COPY VERSIONS.env /src/VERSIONS.env
COPY build/package/build-centos-package.sh /usr/local/bin/build-centos-package
RUN chmod 0755 /usr/local/bin/build-centos-package
CMD ["/usr/local/bin/build-centos-package"]
