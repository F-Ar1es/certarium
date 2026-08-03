package pki

import (
	"fmt"
	"strings"
)

type CertificateKind string

const (
	KindRSA      CertificateKind = "rsa-server"
	KindTLCPSign CertificateKind = "tlcp-sign"
	KindTLCPEnc  CertificateKind = "tlcp-enc"
)

func BuildExtensionConfig(req Request, kind CertificateKind) (string, error) {
	if err := ValidateRequest(req); err != nil {
		return "", err
	}
	var keyUsage string
	switch kind {
	case KindRSA:
		keyUsage = "digitalSignature,keyEncipherment"
	case KindTLCPSign:
		keyUsage = "digitalSignature"
	case KindTLCPEnc:
		keyUsage = "keyEncipherment,dataEncipherment,keyAgreement"
	default:
		return "", fmt.Errorf("unknown certificate kind %q", kind)
	}

	var config strings.Builder
	config.WriteString("[server_cert]\n")
	config.WriteString("basicConstraints=critical,CA:FALSE\n")
	config.WriteString("subjectKeyIdentifier=hash\n")
	config.WriteString("authorityKeyIdentifier=keyid,issuer\n")
	fmt.Fprintf(&config, "keyUsage=critical,%s\n", keyUsage)
	config.WriteString("extendedKeyUsage=serverAuth\n")
	if len(req.DNSNames)+len(req.IPAddresses) > 0 {
		config.WriteString("subjectAltName=@alt_names\n\n[alt_names]\n")
		for i, name := range req.DNSNames {
			fmt.Fprintf(&config, "DNS.%d=%s\n", i+1, name)
		}
		for i, ip := range req.IPAddresses {
			fmt.Fprintf(&config, "IP.%d=%s\n", i+1, ip.String())
		}
	}
	return config.String(), nil
}
