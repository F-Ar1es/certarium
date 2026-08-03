# Installation and first use

Install the matching x86_64 release package:

```sh
sudo yum install ./certarium-0.1.0-1.el7.x86_64.rpm
# or
sudo apt install ./certarium_0.1.0-1_amd64.deb
```

Installation creates `/etc/certarium/ca.pass` once with 256 random bits, owner
`certarium`, and mode 0400. It does not initialize a CA. Start the service and
use an SSH tunnel because the listener is deliberately local:

```sh
sudo systemctl enable --now certarium
ssh -L 8080:127.0.0.1:8080 user@server
```

Open `http://127.0.0.1:8080`, initialize the private lab CA, and issue RSA or
TLCP certificates. Server-side key generation requires explicit confirmation;
full bundles contain private keys. Import downloaded RSA/SM2 roots only into
intended test clients—these are not public trust anchors.
