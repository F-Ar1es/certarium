package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

var version = "dev"

type config struct {
	Listen  string
	DataDir string
}

type health struct {
	Status  string `json:"status"`
	Version string `json:"version"`
	Time    string `json:"time"`
}

var home = template.Must(template.New("home").Parse(`<!doctype html>
<html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>Certarium</title><style>
body{font:16px system-ui;max-width:920px;margin:64px auto;padding:0 24px;color:#18202a}
.card{border:1px solid #d9e0e7;border-radius:14px;padding:24px;box-shadow:0 8px 30px #16202a0d}
.tag{display:inline-block;background:#e8f6ee;color:#176b3a;padding:5px 10px;border-radius:999px}
</style><body><main class="card"><span class="tag">服务已启动</span>
<h1>Certarium</h1><p>标准证书与国密证书实验工作台。</p>
<p>当前为 v0.1 骨架：下一步接入 CA 初始化、RSA 证书和 TLCP 双证书签发。</p>
</main></body></html>`))

func main() {
	listen := flag.String("listen", "127.0.0.1:8080", "HTTP listen address")
	dataDir := flag.String("data-dir", "./data", "state directory")
	showVersion := flag.Bool("version", false, "print version")
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return
	}
	cfg := config{Listen: *listen, DataDir: *dataDir}
	if err := os.MkdirAll(cfg.DataDir, 0700); err != nil {
		log.Fatal(err)
	}
	if err := os.Chmod(cfg.DataDir, 0700); err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := home.Execute(w, nil); err != nil { log.Printf("render home: %v", err) }
	})
	mux.HandleFunc("GET /api/v1/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(health{Status: "ok", Version: version, Time: time.Now().UTC().Format(time.RFC3339)})
	})
	mux.HandleFunc("GET /api/v1/status", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, err := os.Stat(filepath.Join(cfg.DataDir, "pki"))
		_ = json.NewEncoder(w).Encode(map[string]any{"initialized": err == nil, "data_dir": cfg.DataDir})
	})

	server := &http.Server{Addr: cfg.Listen, Handler: securityHeaders(mux), ReadHeaderTimeout: 5 * time.Second}
	log.Printf("Certarium %s listening on %s", version, cfg.Listen)
	log.Fatal(server.ListenAndServe())
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'")
		next.ServeHTTP(w, r)
	})
}
