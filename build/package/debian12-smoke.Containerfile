FROM docker.io/library/debian:12-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends adduser ca-certificates curl systemd-sysv util-linux \
 && rm -rf /var/lib/apt/lists/*
COPY tools/installed-package-smoke.sh /usr/local/bin/installed-package-smoke
COPY build/package/test-installed-deb.sh /usr/local/bin/test-installed-package
RUN chmod 0755 /usr/local/bin/installed-package-smoke /usr/local/bin/test-installed-package
CMD ["/usr/local/bin/test-installed-package"]
