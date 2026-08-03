package webapp

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"certarium/internal/audit"
)

var (
	ErrConflict       = errors.New("resource conflict")
	ErrInvalid        = errors.New("invalid request")
	ErrFileNotAllowed = errors.New("file is not available")
	ErrCryptoTimeout  = errors.New("cryptographic operation timed out")
	ErrCryptoFailure  = errors.New("cryptographic operation failed")
)

type Status struct {
	Initialized bool `json:"initialized"`
}

type IssueRequest struct {
	Name                       string   `json:"name"`
	CommonName                 string   `json:"common_name"`
	DNSNames                   []string `json:"dns_names,omitempty"`
	IPAddresses                []string `json:"ip_addresses,omitempty"`
	ValidDays                  int      `json:"valid_days"`
	ConfirmServerKeyGeneration bool     `json:"confirm_server_key_generation"`
}

type CertificateRecord struct {
	ID          string   `json:"id"`
	Kind        string   `json:"kind"`
	State       string   `json:"state"`
	Serials     []uint64 `json:"serials,omitempty"`
	Purpose     string   `json:"purpose,omitempty"`
	CommonName  string   `json:"common_name,omitempty"`
	DNSNames    []string `json:"dns_names,omitempty"`
	IPAddresses []string `json:"ip_addresses,omitempty"`
	ValidDays   int      `json:"valid_days,omitempty"`
	IssuedAt    string   `json:"issued_at,omitempty"`
	ExpiresAt   string   `json:"expires_at,omitempty"`
}

type Download struct {
	Name        string
	ContentType string
	Data        []byte
	Private     bool
}

type Service interface {
	Status(context.Context) (Status, error)
	Initialize(context.Context, string) error
	Issue(context.Context, string, IssueRequest) (CertificateRecord, error)
	List(context.Context) ([]CertificateRecord, error)
	Download(context.Context, string, string) (Download, error)
	Bundle(context.Context, string) (Download, error)
	RootCA(context.Context, string) (Download, error)
	Revoke(context.Context, string) (CertificateRecord, error)
	CRL(context.Context, string) (Download, error)
	OCSP(context.Context, string, []byte) ([]byte, error)
}

type Options struct {
	Service Service
	Version string
	Auditor *audit.Log
}

type handler struct {
	service Service
	version string
	mux     *http.ServeMux
}

func New(options Options) http.Handler {
	h := &handler{service: options.Service, version: options.Version, mux: http.NewServeMux()}
	h.mux.HandleFunc("GET /", h.home)
	h.mux.HandleFunc("GET /app.js", h.script)
	h.mux.HandleFunc("GET /api/v1/health", h.health)
	h.mux.HandleFunc("GET /api/v1/status", h.status)
	h.mux.HandleFunc("POST /api/v1/initialize", h.initialize)
	h.mux.HandleFunc("GET /api/v1/certificates", h.list)
	h.mux.HandleFunc("POST /api/v1/certificates/{kind}", h.issue)
	h.mux.HandleFunc("GET /api/v1/certificates/{id}/files/{file}", h.download)
	h.mux.HandleFunc("GET /api/v1/certificates/{id}/bundle.zip", h.bundle)
	h.mux.HandleFunc("GET /api/v1/ca/{kind}", h.rootCA)
	h.mux.HandleFunc("POST /api/v1/certificates/{id}/revoke", h.revoke)
	h.mux.HandleFunc("GET /api/v1/crl/{kind}", h.crl)
	h.mux.HandleFunc("POST /ocsp/{kind}", h.ocsp)
	base := securityHeaders(h)
	if options.Auditor != nil {
		return auditRequests(base, options.Auditor)
	}
	return base
}

func (h *handler) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"status": "ok", "version": h.version, "time": time.Now().UTC().Format(time.RFC3339),
	})
}

func (h *handler) home(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = io.WriteString(w, homePage)
}

func (h *handler) script(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	_, _ = io.WriteString(w, applicationJS)
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mux.ServeHTTP(w, r)
}

func (h *handler) status(w http.ResponseWriter, r *http.Request) {
	status, err := h.service.Status(r.Context())
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, struct {
		Status
		Version string `json:"version"`
	}{Status: status, Version: h.version})
}

func (h *handler) initialize(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Organization string `json:"organization"`
	}
	if err := decodeMutation(w, r, &input); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_request", "请求格式无效")
		return
	}
	if strings.TrimSpace(input.Organization) == "" {
		writeAPIError(w, http.StatusBadRequest, "invalid_request", "组织名称不能为空")
		return
	}
	if err := h.service.Initialize(r.Context(), input.Organization); err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]bool{"initialized": true})
}

func (h *handler) list(w http.ResponseWriter, r *http.Request) {
	records, err := h.service.List(r.Context())
	if err != nil {
		writeServiceError(w, err)
		return
	}
	if records == nil {
		records = []CertificateRecord{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"certificates": records})
}

func (h *handler) issue(w http.ResponseWriter, r *http.Request) {
	kind := r.PathValue("kind")
	if kind != "rsa" && kind != "tlcp" {
		writeAPIError(w, http.StatusNotFound, "not_found", "资源不存在")
		return
	}
	var input IssueRequest
	if err := decodeMutation(w, r, &input); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_request", "请求格式无效")
		return
	}
	if !input.ConfirmServerKeyGeneration {
		writeAPIError(w, http.StatusBadRequest, "key_confirmation_required", "必须明确确认由服务端生成私钥")
		return
	}
	record, err := h.service.Issue(r.Context(), kind, input)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, record)
}

func (h *handler) download(w http.ResponseWriter, r *http.Request) {
	download, err := h.service.Download(r.Context(), r.PathValue("id"), r.PathValue("file"))
	if err != nil {
		if errors.Is(err, ErrFileNotAllowed) {
			writeAPIError(w, http.StatusNotFound, "not_found", "资源不存在")
			return
		}
		writeServiceError(w, err)
		return
	}
	serveDownload(w, download)
}

func (h *handler) bundle(w http.ResponseWriter, r *http.Request) {
	download, err := h.service.Bundle(r.Context(), r.PathValue("id"))
	if err != nil {
		writeServiceError(w, err)
		return
	}
	serveDownload(w, download)
}

func (h *handler) rootCA(w http.ResponseWriter, r *http.Request) {
	download, err := h.service.RootCA(r.Context(), r.PathValue("kind"))
	if err != nil {
		writeServiceError(w, err)
		return
	}
	serveDownload(w, download)
}

func (h *handler) revoke(w http.ResponseWriter, r *http.Request) {
	var empty struct{}
	if err := decodeMutation(w, r, &empty); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_request", "请求格式无效")
		return
	}
	record, err := h.service.Revoke(r.Context(), r.PathValue("id"))
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, record)
}

func (h *handler) crl(w http.ResponseWriter, r *http.Request) {
	download, err := h.service.CRL(r.Context(), r.PathValue("kind"))
	if err != nil {
		if errors.Is(err, ErrFileNotAllowed) {
			writeAPIError(w, http.StatusNotFound, "not_found", "资源不存在")
			return
		}
		writeServiceError(w, err)
		return
	}
	serveDownload(w, download)
}

func (h *handler) ocsp(w http.ResponseWriter, r *http.Request) {
	kind := r.PathValue("kind")
	if kind != "rsa" && kind != "sm2" {
		writeAPIError(w, http.StatusNotFound, "not_found", "资源不存在")
		return
	}
	media := strings.ToLower(strings.TrimSpace(strings.Split(r.Header.Get("Content-Type"), ";")[0]))
	if media != "application/ocsp-request" {
		writeAPIError(w, http.StatusBadRequest, "invalid_ocsp_request", "OCSP 请求格式无效")
		return
	}
	if origin := r.Header.Get("Origin"); origin != "" && !sameOrigin(r, origin) {
		writeAPIError(w, http.StatusBadRequest, "invalid_ocsp_request", "OCSP 请求来源无效")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16*1024)
	request, err := io.ReadAll(r.Body)
	if err != nil || len(request) == 0 {
		writeAPIError(w, http.StatusBadRequest, "invalid_ocsp_request", "OCSP 请求格式无效")
		return
	}
	response, err := h.service.OCSP(r.Context(), kind, request)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/ocsp-response")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(response)
}

func serveDownload(w http.ResponseWriter, download Download) {
	if download.Private {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
	}
	w.Header().Set("Content-Type", download.ContentType)
	w.Header().Set("Content-Disposition", "attachment; filename="+strconv.Quote(download.Name))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(download.Data)
}

const maxJSONBody = 64 * 1024

func decodeMutation(w http.ResponseWriter, r *http.Request, destination any) error {
	if media := strings.ToLower(strings.TrimSpace(strings.Split(r.Header.Get("Content-Type"), ";")[0])); media != "application/json" {
		return errors.New("content type must be application/json")
	}
	if origin := r.Header.Get("Origin"); origin != "" && !sameOrigin(r, origin) {
		return errors.New("cross-origin mutation rejected")
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxJSONBody)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("request contains multiple JSON values")
	}
	return nil
}

func sameOrigin(r *http.Request, origin string) bool {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return origin == scheme+"://"+r.Host
}

func writeServiceError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrFileNotAllowed):
		writeAPIError(w, http.StatusNotFound, "not_found", "资源不存在")
	case errors.Is(err, ErrInvalid):
		writeAPIError(w, http.StatusBadRequest, "invalid_request", "请求参数无效")
	case errors.Is(err, ErrConflict):
		writeAPIError(w, http.StatusConflict, "conflict", "资源已经存在")
	case errors.Is(err, ErrCryptoTimeout):
		writeAPIError(w, http.StatusGatewayTimeout, "crypto_timeout", "密码操作超时")
	case errors.Is(err, ErrCryptoFailure):
		writeAPIError(w, http.StatusBadGateway, "crypto_failure", "密码操作失败")
	default:
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "服务内部错误")
	}
}

func writeAPIError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]string{"code": code, "message": message})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'")
		next.ServeHTTP(w, r)
	})
}

func IsLoopbackListen(address string) bool {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

type bufferedResponse struct {
	header http.Header
	body   bytes.Buffer
	status int
}

func (w *bufferedResponse) Header() http.Header { return w.header }
func (w *bufferedResponse) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
}
func (w *bufferedResponse) Write(data []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.body.Write(data)
}

func auditRequests(next http.Handler, log *audit.Log) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		action, resource, required := auditTarget(r)
		if !required {
			next.ServeHTTP(w, r)
			return
		}
		requestID, err := newRequestID()
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, "audit_failure", "审计记录不可用")
			return
		}
		if err := log.Ready(); err != nil {
			writeAPIError(w, http.StatusInternalServerError, "audit_failure", "审计记录不可用")
			return
		}
		capture := &bufferedResponse{header: make(http.Header)}
		next.ServeHTTP(capture, r)
		if capture.status == 0 {
			capture.status = http.StatusOK
		}
		outcome := "success"
		errorCode := ""
		if capture.status >= 400 {
			outcome = "failure"
			var body struct {
				Code string `json:"code"`
			}
			_ = json.Unmarshal(capture.body.Bytes(), &body)
			errorCode = body.Code
		}
		if err := log.Append(audit.Record{
			Time: time.Now().UTC(), RequestID: requestID, RemoteAddr: r.RemoteAddr,
			Action: action, Resource: resource, Outcome: outcome, ErrorCode: errorCode,
		}); err != nil {
			writeAPIError(w, http.StatusInternalServerError, "audit_failure", "审计记录不可用")
			return
		}
		for name, values := range capture.header {
			w.Header()[name] = append([]string(nil), values...)
		}
		w.Header().Set("X-Request-ID", requestID)
		w.WriteHeader(capture.status)
		_, _ = w.Write(capture.body.Bytes())
	})
}

func auditTarget(r *http.Request) (string, string, bool) {
	path := strings.Trim(r.URL.Path, "/")
	parts := strings.Split(path, "/")
	switch {
	case r.Method == http.MethodPost && path == "api/v1/initialize":
		return "initialize", "ca", true
	case r.Method == http.MethodPost && len(parts) == 4 && strings.Join(parts[:3], "/") == "api/v1/certificates":
		return "issue", parts[3], true
	case r.Method == http.MethodPost && len(parts) == 5 && strings.Join(parts[:3], "/") == "api/v1/certificates" && parts[4] == "revoke":
		return "revoke", parts[3], true
	case r.Method == http.MethodGet && len(parts) == 6 && strings.Join(parts[:3], "/") == "api/v1/certificates" && parts[4] == "files":
		return "download", parts[3] + "/" + parts[5], true
	case r.Method == http.MethodGet && len(parts) == 5 && strings.Join(parts[:3], "/") == "api/v1/certificates" && parts[4] == "bundle.zip":
		return "download_bundle", parts[3], true
	default:
		return "", "", false
	}
}

func newRequestID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", fmt.Errorf("generate request ID: %w", err)
	}
	return fmt.Sprintf("%x", value[:]), nil
}
