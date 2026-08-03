# Core build notes

The core is built in a CentOS 7 userspace to keep its glibc symbol baseline at
2.17 or older. Apple container runs the amd64 build under Rosetta on Apple
Silicon.

The build intentionally excludes HTTP gzip and HTTP Basic Authentication:

- Disabling gzip avoids Nginx certificate-compression feature detection against
  a TLS library that does not expose the BoringSSL `CBB` API.
- Disabling Basic Authentication avoids a runtime dependency on `libcrypt`.

Neither module is required for TLS/TLCP termination, reverse proxying, load
balancing, OCSP publication or the future Web control plane.

PCRE2 and Tongsuo are compiled into the Nginx binary. The resulting archive
contains dependency and glibc symbol reports which must be reviewed before it is
accepted as CentOS 7 compatible.

