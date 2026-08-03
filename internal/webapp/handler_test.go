package webapp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"certarium/internal/audit"
)

type fakeService struct {
	initialized bool
	initErr     error
	issuedKind  string
	issued      IssueRequest
	issueCalls  int
}

func TestMutationAndDownloadAttemptsAreAuditedWithoutBodies(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	h := New(Options{Service: &fakeService{}, Auditor: audit.New(path)})
	requests := []*http.Request{
		httptest.NewRequest(http.MethodPost, "/api/v1/certificates/rsa", bytes.NewBufferString(`{"name":"audit-item","common_name":"secret-canary.test","valid_days":30,"confirm_server_key_generation":true}`)),
		httptest.NewRequest(http.MethodGet, "/api/v1/certificates/audit-item/files/server-rsa.key", nil),
	}
	requests[0].Header.Set("Content-Type", "application/json")
	for _, request := range requests {
		request.RemoteAddr = "127.0.0.1:43210"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, request)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSpace(data), []byte{'\n'})
	if len(lines) != 2 {
		t.Fatalf("audit lines = %d: %s", len(lines), data)
	}
	for _, line := range lines {
		var record audit.Record
		if err := json.Unmarshal(line, &record); err != nil {
			t.Fatal(err)
		}
		if record.RequestID == "" || record.RemoteAddr != "127.0.0.1:43210" || record.Action == "" || record.Outcome == "" {
			t.Fatalf("incomplete audit record: %#v", record)
		}
	}
	for _, secret := range []string{"secret-canary.test", "PRIVATE KEY", "confirm_server_key_generation"} {
		if bytes.Contains(data, []byte(secret)) {
			t.Fatalf("audit leaked %q: %s", secret, data)
		}
	}
}

func (f *fakeService) Status(context.Context) (Status, error) {
	return Status{Initialized: f.initialized}, nil
}

func (f *fakeService) Initialize(_ context.Context, organization string) error {
	if f.initErr != nil {
		return f.initErr
	}
	f.initialized = true
	return nil
}

func (f *fakeService) Issue(_ context.Context, kind string, req IssueRequest) (CertificateRecord, error) {
	f.issueCalls++
	f.issuedKind, f.issued = kind, req
	return CertificateRecord{ID: req.Name, Kind: kind}, nil
}

func TestAuditUnavailableFailsIssuanceClosed(t *testing.T) {
	svc := &fakeService{}
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	if err := os.Mkdir(auditPath, 0700); err != nil {
		t.Fatal(err)
	}
	h := New(Options{Service: svc, Auditor: audit.New(auditPath)})
	r := httptest.NewRequest(http.MethodPost, "/api/v1/certificates/rsa", bytes.NewBufferString(`{"name":"blocked","common_name":"blocked.test","valid_days":30,"confirm_server_key_generation":true}`))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusInternalServerError || !strings.Contains(w.Body.String(), `"code":"audit_failure"`) {
		t.Fatalf("response: status=%d body=%s", w.Code, w.Body.String())
	}
	if svc.issueCalls != 0 {
		t.Fatalf("issuance ran %d times while audit was unavailable", svc.issueCalls)
	}
}

func (f *fakeService) List(context.Context) ([]CertificateRecord, error) { return nil, nil }

func (f *fakeService) Download(context.Context, string, string) (Download, error) {
	return Download{}, ErrFileNotAllowed
}
func (f *fakeService) Bundle(context.Context, string) (Download, error) {
	return Download{}, ErrFileNotAllowed
}
func (f *fakeService) RootCA(context.Context, string) (Download, error) {
	return Download{}, ErrFileNotAllowed
}

func (f *fakeService) Revoke(_ context.Context, id string) (CertificateRecord, error) {
	return CertificateRecord{ID: id, State: "revoked"}, nil
}

func (f *fakeService) CRL(context.Context, string) (Download, error) {
	return Download{Name: "rsa.crl.pem", ContentType: "application/pkix-crl", Data: []byte("CRL")}, nil
}

func (f *fakeService) OCSP(_ context.Context, kind string, request []byte) ([]byte, error) {
	return append([]byte(kind+":"), request...), nil
}

func TestStatusDoesNotExposeDataDirectory(t *testing.T) {
	h := New(Options{Service: &fakeService{initialized: true}, Version: "test"})
	r := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	if bytes.Contains(w.Body.Bytes(), []byte("data_dir")) || bytes.Contains(w.Body.Bytes(), []byte("/tmp")) {
		t.Fatalf("response exposes filesystem details: %s", w.Body.String())
	}
}

func TestInitializeRejectsUnknownFieldsAndMapsConflict(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		svc  *fakeService
		want int
	}{
		{"unknown field", `{"organization":"Lab","extra":true}`, &fakeService{}, http.StatusBadRequest},
		{"already initialized", `{"organization":"Lab"}`, &fakeService{initErr: ErrConflict}, http.StatusConflict},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := New(Options{Service: tc.svc})
			r := httptest.NewRequest(http.MethodPost, "/api/v1/initialize", bytes.NewBufferString(tc.body))
			r.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != tc.want {
				t.Fatalf("status = %d, want %d: %s", w.Code, tc.want, w.Body.String())
			}
		})
	}
}

func TestIssuanceRequiresExplicitServerKeyConfirmation(t *testing.T) {
	svc := &fakeService{}
	h := New(Options{Service: svc})
	body := map[string]any{"name": "gateway", "common_name": "gateway.test", "valid_days": 30}
	encoded, _ := json.Marshal(body)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/certificates/rsa", bytes.NewReader(encoded))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", w.Code, w.Body.String())
	}
	if svc.issuedKind != "" {
		t.Fatal("issuance reached service without explicit key confirmation")
	}
}

func TestDownloadDenyDoesNotLeakInternalPath(t *testing.T) {
	h := New(Options{Service: &fakeService{}})
	r := httptest.NewRequest(http.MethodGet, "/api/v1/certificates/gateway/files/root-ca.key", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
	if bytes.Contains(w.Body.Bytes(), []byte("root-ca.key")) {
		t.Fatalf("denial leaks requested internal filename: %s", w.Body.String())
	}
}

func TestErrorResponseIsStableJSON(t *testing.T) {
	h := New(Options{Service: &fakeService{initErr: errors.New("/secret/path: crypto output")}})
	r := httptest.NewRequest(http.MethodPost, "/api/v1/initialize", bytes.NewBufferString(`{"organization":"Lab"}`))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d", w.Code)
	}
	if bytes.Contains(w.Body.Bytes(), []byte("secret")) || bytes.Contains(w.Body.Bytes(), []byte("crypto output")) {
		t.Fatalf("internal error leaked: %s", w.Body.String())
	}
	var got map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil || got["code"] == "" || got["message"] == "" {
		t.Fatalf("unstable error JSON: %s", w.Body.String())
	}
}

func TestOnlyExplicitLoopbackListenersAreAccepted(t *testing.T) {
	for _, address := range []string{"127.0.0.1:8080", "[::1]:8080"} {
		if !IsLoopbackListen(address) {
			t.Errorf("loopback address %q rejected", address)
		}
	}
	for _, address := range []string{"0.0.0.0:8080", ":8080", "192.168.1.10:8080", "localhost:8080", "bad"} {
		if IsLoopbackListen(address) {
			t.Errorf("non-explicit loopback address %q accepted", address)
		}
	}
}

func TestLocalWebUIAndScriptAreServedSafely(t *testing.T) {
	h := New(Options{Service: &fakeService{}, Version: "test"})
	for _, tc := range []struct {
		path        string
		contentType string
		want        string
	}{
		{"/", "text/html", "Certarium"},
		{"/app.js", "text/javascript", "textContent"},
	} {
		r := httptest.NewRequest(http.MethodGet, tc.path, nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusOK || !strings.HasPrefix(w.Header().Get("Content-Type"), tc.contentType) || !strings.Contains(w.Body.String(), tc.want) {
			t.Fatalf("GET %s: status=%d type=%q body=%q", tc.path, w.Code, w.Header().Get("Content-Type"), w.Body.String())
		}
		if strings.Contains(w.Body.String(), "innerHTML") || strings.Contains(w.Body.String(), "document.write") {
			t.Fatalf("unsafe DOM rendering primitive in %s", tc.path)
		}
	}
}

func TestRevokeAndCRLRoutes(t *testing.T) {
	h := New(Options{Service: &fakeService{}})
	revoke := httptest.NewRequest(http.MethodPost, "/api/v1/certificates/gateway/revoke", bytes.NewBufferString(`{}`))
	revoke.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, revoke)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"state":"revoked"`) {
		t.Fatalf("revoke response: status=%d body=%s", w.Code, w.Body.String())
	}

	request := httptest.NewRequest(http.MethodGet, "/api/v1/crl/rsa", nil)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, request)
	if w.Code != http.StatusOK || w.Header().Get("Content-Type") != "application/pkix-crl" || w.Body.String() != "CRL" {
		t.Fatalf("CRL response: status=%d type=%q body=%q", w.Code, w.Header().Get("Content-Type"), w.Body.String())
	}
}

func TestStandardOCSPRouteEnforcesMIMEAndBodyLimit(t *testing.T) {
	h := New(Options{Service: &fakeService{}})
	request := httptest.NewRequest(http.MethodPost, "/ocsp/rsa", bytes.NewReader([]byte("DER")))
	request.Header.Set("Content-Type", "application/ocsp-request")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, request)
	if w.Code != http.StatusOK || w.Header().Get("Content-Type") != "application/ocsp-response" || w.Body.String() != "rsa:DER" {
		t.Fatalf("OCSP response: status=%d type=%q body=%q", w.Code, w.Header().Get("Content-Type"), w.Body.String())
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("OCSP response is cacheable")
	}

	for _, tc := range []struct {
		name string
		kind string
		body []byte
		mime string
	}{
		{"wrong MIME", "rsa", []byte("DER"), "application/json"},
		{"empty", "rsa", nil, "application/ocsp-request"},
		{"oversized", "rsa", bytes.Repeat([]byte("x"), 16*1024+1), "application/ocsp-request"},
		{"bad issuer", "other", []byte("DER"), "application/ocsp-request"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/ocsp/"+tc.kind, bytes.NewReader(tc.body))
			r.Header.Set("Content-Type", tc.mime)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != http.StatusBadRequest && w.Code != http.StatusNotFound {
				t.Fatalf("status = %d: %s", w.Code, w.Body.String())
			}
		})
	}
}
