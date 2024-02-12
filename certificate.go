package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"log"
	"math/big"
	"os"
	"path"
	"time"

	"software.sslmate.com/src/go-pkcs12"
)

func createCertificate(name, password string, caCert *x509.Certificate, caKey *ecdsa.PrivateKey) (err error) {

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
		key, err = rsa.GenerateKey(rand.Reader, 3192)
		if err != nil {
			return err
		}
		log.Println("Client private key created -", name)
	}

	// Create client certificate
	log.Println("Creating client certificate -", name)
	now := time.Now()
	template := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName:   name,
			SerialNumber: name + " " + now.Format("2006-01-02"),
			Organization: []string{config.CertTemplate.Organization},
			Country:      []string{config.CertTemplate.Country},
			Locality:     []string{config.CertTemplate.Locality},
		},
		NotBefore:   now,
		NotAfter:    now.AddDate(0, 0, config.CertTemplate.ValidityDays),
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

	// Save client certificate
	pfx, err := pkcs12.Modern.Encode(key, cert, nil, password)
	if err != nil {
		return err
	}
	err = os.WriteFile(path.Join(config.CertDir, cert.Subject.CommonName+" "+now.Format("2006-01-02")+".p12"), pfx, 0600)
	if err != nil {
		return err
	}

	log.Println("Client certificate saved -", name)

	return nil
}
