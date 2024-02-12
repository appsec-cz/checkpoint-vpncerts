package main

import (
	"errors"
	"flag"
	"log"
	"os"

	"gopkg.in/yaml.v2"
)

var (
	Help                = flag.Bool("help", false, "Show help")
	CertificateName     = flag.String("name", "", "Name of the client certificate")
	CertificatePassword = flag.String("password", "", "Password for the client certificate")
)

func main() {

	// Parse command line arguments
	flag.Parse()
	if *Help || flag.NFlag() == 0 {
		flag.Usage()
		os.Exit(0)
	}
	name := *CertificateName
	if name == "" {
		log.Fatal("Name of the certificate is not set. Run with argument -name <name>")
	}
	password := *CertificatePassword
	if password == "" {
		log.Fatal("Password for the certificate is not set. Run with argument -password <password>")
	}

	// Load configuration
	log.Println("Loading configuration")
	config.CertDir = "certs"
	configFile, err := os.ReadFile("config.yml")
	if err != nil {
		log.Fatal(err)
	}
	err = yaml.Unmarshal(configFile, &config)
	if err != nil {
		log.Fatal(err)
	}
	if config.CertTemplate.Country == "" {
		log.Fatal("Country in certificate template is not set in config")
	}
	if config.CertTemplate.Organization == "" {
		log.Fatal("Organization in certificate template is not set in config")
	}
	log.Println("Configuration loaded")

	// Create certificate directory
	if _, err := os.Stat(config.CertDir); errors.Is(err, os.ErrNotExist) {
		log.Println("Creating certificate directory")
		err := os.Mkdir(config.CertDir, os.ModePerm)
		if err != nil {
			log.Fatal(err)
		}
	}

	// Process CA certificate
	caCert, caKey, err := getCA(name)
	if err != nil {
		log.Fatalln(err)
	}

	// Process client certificate
	err = createCertificate(name, password, caCert, caKey)
	if err != nil {
		log.Fatalln(err)
	}

}
