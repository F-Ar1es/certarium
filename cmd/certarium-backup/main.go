package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"certarium/internal/backup"
	"certarium/internal/pki"
)

var version = "dev"

func main() {
	mode := flag.String("mode", "", "backup or restore")
	dataDir := flag.String("data-dir", "/var/lib/certarium", "Certarium data directory")
	configDir := flag.String("config-dir", "/etc/certarium", "Certarium configuration directory")
	artifact := flag.String("file", "", "encrypted backup artifact")
	passwordFile := flag.String("passphrase-file", "", "private file containing the backup password")
	replace := flag.Bool("replace", false, "replace existing state during restore")
	showVersion := flag.Bool("version", false, "print version")
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return
	}
	if *artifact == "" {
		log.Fatal("-file is required")
	}
	password, err := pki.LoadPassphraseFile(*passwordFile)
	if err != nil {
		log.Fatal(err)
	}
	switch *mode {
	case "backup":
		if *replace {
			log.Fatal("-replace is valid only for restore")
		}
		err = backup.Create(*dataDir, *configDir, *artifact, password)
	case "restore":
		err = backup.Restore(*artifact, *dataDir, *configDir, password, *replace)
	default:
		log.Fatal("-mode must be backup or restore")
	}
	if err != nil {
		log.Fatal(err)
	}
	if _, err := os.Stdout.WriteString(*mode + " completed\n"); err != nil {
		log.Fatal(err)
	}
}
