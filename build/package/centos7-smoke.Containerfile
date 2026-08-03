FROM quay.io/centos/centos:7
RUN printf '%s\n' \
      '[base]' 'name=CentOS-7 - Base' 'baseurl=http://archive.kernel.org/centos-vault/7.9.2009/os/$basearch/' 'enabled=1' 'gpgcheck=0' \
      '[updates]' 'name=CentOS-7 - Updates' 'baseurl=http://archive.kernel.org/centos-vault/7.9.2009/updates/$basearch/' 'enabled=1' 'gpgcheck=0' \
      '[extras]' 'name=CentOS-7 - Extras' 'baseurl=http://archive.kernel.org/centos-vault/7.9.2009/extras/$basearch/' 'enabled=1' 'gpgcheck=0' \
      > /etc/yum.repos.d/CentOS-Base.repo \
 && yum -y install curl shadow-utils util-linux \
 && yum clean all && rm -rf /var/cache/yum
COPY tools/installed-package-smoke.sh /usr/local/bin/installed-package-smoke
COPY build/package/test-installed-rpm.sh /usr/local/bin/test-installed-package
RUN chmod 0755 /usr/local/bin/installed-package-smoke /usr/local/bin/test-installed-package
CMD ["/usr/local/bin/test-installed-package"]
