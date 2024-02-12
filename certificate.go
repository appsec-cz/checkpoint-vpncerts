package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"log"
	"math/big"
	"os"
	"path"
	"strings"
	"time"

	"software.sslmate.com/src/go-pkcs12"
)

func createCertificate(name, password string, caCert *x509.Certificate, caKey *rsa.PrivateKey) (err error) {

	var key *rsa.PrivateKey

	if _, err := os.Stat(path.Join(config.CertDir, name+".p12")); err == nil {
		// Load certificate and key
		log.Println("Loading client private key -", name)
		pkcs12Data, err := os.ReadFile(path.Join(config.CertDir, name+".p12"))
		if err != nil {
			return err
		}
		k, _, err := pkcs12.Decode(pkcs12Data, password)
		if err != nil {
			return err
		}
		if _, ok := k.(*rsa.PrivateKey); !ok {
			return errors.New("unspuuportd format of private key in p12 file")
		}
		key = k.(*rsa.PrivateKey)
	} else {
		// Create client private key
		log.Println("Creating client private key -", name)
		key, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return err
		}
		log.Println("Client private key created -", name)
	}

	// Create client certificate
	log.Println("Creating client certificate -", name)
	template := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName:   name,
			SerialNumber: strings.ReplaceAll(name, " ", "_"),
			Organization: []string{config.CertTemplate.Organization},
			Country:      []string{config.CertTemplate.Country},
			Locality:     []string{"Prague"},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(2 * 365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsage(x509.KeyUsageDigitalSignature),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageIPSECUser, x509.ExtKeyUsageClientAuth},
		Extensions:  []pkix.Extension{},
	}
	c, err := x509.CreateCertificate(rand.Reader, &template, caCert, &key.PublicKey, caKey)
	if err != nil {
		return err
	}
	cert, err := x509.ParseCertificate(c)
	if err != nil {
		return err
	}
	log.Println("Client certificate created -", name)

	err = saveCertificate(name, password, cert, key)
	if err != nil {
		return err
	}

	return nil
}

func saveCertificate(name, password string, cert *x509.Certificate, key *rsa.PrivateKey) error {
	pfx, err := pkcs12.Modern.Encode(key, cert, nil, password)
	if err != nil {
		return err
	}
	err = os.WriteFile(path.Join(config.CertDir, cert.Subject.CommonName+".p12"), pfx, 0644)
	if err != nil {
		return err
	}

	log.Println("Client certificate saved -", name)

	return nil
}
