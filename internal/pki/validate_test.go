package pki

import (
	"net"
	"strings"
	"testing"
)

func TestValidateRequestAcceptsDNSIPv4AndIPv6(t *testing.T) {
	req := Request{
		Name:        "gateway-01",
		CommonName:  "gateway.lab.example",
		DNSNames:    []string{"gateway.lab.example", "api.lab.example"},
		IPAddresses: []net.IP{net.ParseIP("192.0.2.10"), net.ParseIP("2001:db8::10")},
		ValidDays:   397,
	}
	if err := ValidateRequest(req); err != nil {
		t.Fatalf("valid request rejected: %v", err)
	}
}

func TestValidateRequestRejectsHostileAndInvalidInputs(t *testing.T) {
	tests := []struct {
		name string
		req  Request
		want string
	}{
		{"path traversal", Request{Name: "../root", CommonName: "a.example", ValidDays: 30}, "name"},
		{"newline injection", Request{Name: "safe", CommonName: "a.example\nDNS.1=evil", ValidDays: 30}, "common name"},
		{"bad DNS", Request{Name: "safe", CommonName: "a.example", DNSNames: []string{"bad name"}, ValidDays: 30}, "DNS"},
		{"nil IP", Request{Name: "safe", CommonName: "a.example", IPAddresses: []net.IP{nil}, ValidDays: 30}, "IP"},
		{"zero validity", Request{Name: "safe", CommonName: "a.example", ValidDays: 0}, "validity"},
		{"excess validity", Request{Name: "safe", CommonName: "a.example", ValidDays: 826}, "validity"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateRequest(tc.req)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want text %q", err, tc.want)
			}
		})
	}
}
