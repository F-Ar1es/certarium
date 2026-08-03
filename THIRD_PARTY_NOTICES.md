# Third-party notices

Certarium's Go service currently imports only the Go standard library. Release
packages and interoperability examples may include or build the following
components. They are not relicensed as Certarium code.

| Component | Version baseline | License | Usage |
|---|---:|---|---|
| Go toolchain/runtime | 1.22 | BSD-3-Clause | Builds the static service binary |
| Tongsuo | 8.4.0 | Apache-2.0 | Cryptographic CLI/backend and TLCP support |
| Nginx | 1.30.4 | BSD-2-Clause | Optional interoperability example only |
| PCRE2 | 10.45 | BSD-3-Clause WITH PCRE2-exception | Optional Nginx example dependency |

Binary distributions must reproduce all notices required by these licenses.
Tongsuo NOTICE material, if present in the selected source revision, must also
be included. The Nginx/TLCP patch is a modification of BSD-2-Clause Nginx code
and must retain Nginx attribution and a prominent modification notice.

Authoritative upstream license files:

- https://github.com/golang/go/blob/master/LICENSE
- https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
- https://github.com/nginx/nginx/blob/master/LICENSE
- https://github.com/PCRE2Project/pcre2/blob/pcre2-10.45/LICENCE.md
