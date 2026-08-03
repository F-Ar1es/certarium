package pki

import (
	"net"
	"strings"
	"testing"
)

func TestBuildExtensionConfigUsesPurposeSpecificKeyUsage(t *testing.T) {
	req := Request{
		Name: "gateway", CommonName: "gateway.example",
		DNSNames:    []string{"gateway.example", "api.example"},
		IPAddresses: []net.IP{net.ParseIP("192.0.2.5"), net.ParseIP("2001:db8::5")},
		ValidDays:   397,
	}
	tests := []struct {
		kind   CertificateKind
		usage  string
		forbid string
	}{
		{KindRSA, "keyUsage=critical,digitalSignature,keyEncipherment", "keyAgreement"},
		{KindTLCPSign, "keyUsage=critical,digitalSignature", "keyEncipherment"},
		{KindTLCPEnc, "keyUsage=critical,keyEncipherment,dataEncipherment,keyAgreement", "digitalSignature"},
	}
	for _, tc := range tests {
		t.Run(string(tc.kind), func(t *testing.T) {
			got, err := BuildExtensionConfig(req, tc.kind)
			if err != nil {
				t.Fatalf("build config: %v", err)
			}
			for _, want := range []string{
				"[server_cert]", tc.usage, "extendedKeyUsage=serverAuth",
				"DNS.1=gateway.example", "DNS.2=api.example",
				"IP.1=192.0.2.5", "IP.2=2001:db8::5",
			} {
				if !strings.Contains(got, want) {
					t.Errorf("config missing %q:\n%s", want, got)
				}
			}
			if strings.Contains(got, tc.forbid) {
				t.Errorf("config contains forbidden usage %q", tc.forbid)
			}
		})
	}
}

func TestBuildExtensionConfigRejectsUnknownKindAndUnsafeInput(t *testing.T) {
	good := Request{Name: "safe", CommonName: "safe.example", DNSNames: []string{"safe.example"}, ValidDays: 30}
	if _, err := BuildExtensionConfig(good, CertificateKind("unknown")); err == nil {
		t.Fatal("unknown certificate kind accepted")
	}
	bad := good
	bad.DNSNames = []string{"safe.example\nkeyUsage=CA:TRUE"}
	if _, err := BuildExtensionConfig(bad, KindRSA); err == nil {
		t.Fatal("newline injection accepted")
	}
}
