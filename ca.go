package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"os"
	"path"
	"time"
)

func getCA(name string) (cert *x509.Certificate, key *ecdsa.PrivateKey, err error) {
	dir := path.Join(config.CertDir, name)
	now := time.Now()

	if _, err := os.Stat(path.Join(dir, name+" CA.crt")); err == nil {

		// Load CA certificate
		log.Println("Loading CA certificate -", name)
		certFile, err := os.ReadFile(path.Join(dir, name+" CA.crt"))
		if err != nil {
			return nil, nil, err
		}
		block, _ := pem.Decode(certFile)
		cert, err = x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, nil, err
		}
		log.Println("CA certificate loaded -", name)

		// Load CA key
		log.Println("Loading CA key -", name)
		keyFile, err := os.ReadFile(path.Join(dir, name+" CA.key"))
		if err != nil {
			return nil, nil, err
		}
		block, _ = pem.Decode(keyFile)
		key, err = x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, nil, err
		}
		log.Println("CA key loaded -", name)

		return cert, key, nil
	}

	log.Println("Creating CA certificate -", name)
	key, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	templateCA := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   name,
			Organization: []string{config.CertTemplate.Organization},
			Country:      []string{config.CertTemplate.Country},
			Locality:     []string{config.CertTemplate.Locality},
		},
		NotBefore:             now,
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	c, err := x509.CreateCertificate(rand.Reader, &templateCA, &templateCA, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	cert, err = x509.ParseCertificate(c)
	if err != nil {
		return nil, nil, err
	}
	log.Println("CA certificate created -", name)

	// Save CA certificate and key
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		err = os.Mkdir(dir, 0755)
		if err != nil {
			return nil, nil, err
		}
	}

	certOut, err := os.Create(path.Join(dir, name+" CA.crt"))
	if err != nil {
		return nil, nil, err
	}
	defer certOut.Close()
	err = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	if err != nil {
		return nil, nil, err
	}
	keyOut, err := os.Create(path.Join(dir, name+" CA.key"))
	if err != nil {
		return nil, nil, err
	}
	defer keyOut.Close()
	b, _ := x509.MarshalECPrivateKey(key)
	err = pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: b})
	if err != nil {
		return nil, nil, err
	}
	log.Println("CA saved -", name)

	return cert, key, nil
}
