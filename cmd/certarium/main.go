package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"certarium/internal/audit"
	"certarium/internal/pki"
	"certarium/internal/webapp"
)

var version = "dev"

func main() {
	listen := flag.String("listen", "127.0.0.1:8080", "HTTP listen address (loopback only in v0.1)")
	dataDir := flag.String("data-dir", "./data", "state directory")
	tongsuo := flag.String("tongsuo", "/opt/tongsuo/bin/openssl", "Tongsuo executable")
	cryptoTimeout := flag.Duration("crypto-timeout", 30*time.Second, "cryptographic command timeout")
	passphraseFile := flag.String("ca-passphrase-file", "", "private file containing the CA-key passphrase")
	showVersion := flag.Bool("version", false, "print version")
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return
	}
	if !webapp.IsLoopbackListen(*listen) {
		log.Fatal("v0.1 only supports an explicit loopback listen address")
	}
	passphrase, err := pki.LoadPassphraseFile(*passphraseFile)
	if err != nil {
		log.Fatal(err)
	}
	if err := os.MkdirAll(*dataDir, 0700); err != nil {
		log.Fatal(err)
	}
	if err := os.Chmod(*dataDir, 0700); err != nil {
		log.Fatal(err)
	}

	store := pki.NewStore(*dataDir)
	runner := pki.CommandRunner{Executable: *tongsuo, Timeout: *cryptoTimeout}
	engine := pki.NewEngineWithPassphrase(store, runner, passphrase)
	service := webapp.NewPKIService(*dataDir, store, engine)
	handler := webapp.New(webapp.Options{Service: service, Version: version, Auditor: audit.New(*dataDir + "/audit.jsonl")})
	server := &http.Server{
		Addr:              *listen,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      45 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	log.Printf("Certarium %s listening on %s", version, *listen)
	log.Fatal(server.ListenAndServe())
}
