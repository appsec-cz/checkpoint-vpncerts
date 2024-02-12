package main

var config struct {
	CertDir      string `yaml:"certDir"`
	CertTemplate struct {
		ValidityDays int    `yaml:"validity"`
		Organization string `yaml:"organization"`
		Country      string `yaml:"country"`
	} `yaml:"certTemplate"`
}
