FROM docker.io/library/debian:12-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates dpkg-dev file \
 && rm -rf /var/lib/apt/lists/*
COPY packaging/deb /templates/deb
COPY build/package/build-deb-package.sh /usr/local/bin/build-deb-package
RUN chmod 0755 /usr/local/bin/build-deb-package
CMD ["/usr/local/bin/build-deb-package"]
