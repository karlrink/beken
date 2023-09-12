package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
)

func generateRSAKeyPair() error {
	// Generate a new RSA private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	// Encode the private key to PEM format
	privateKeyFile, err := os.Create("private_key.pem")
	if err != nil {
		return err
	}
	defer privateKeyFile.Close()

	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}

	if err := pem.Encode(privateKeyFile, privateKeyPEM); err != nil {
		return err
	}

	// Extract the public key from the private key
	publicKey := &privateKey.PublicKey

	// Encode the public key to PEM format
	publicKeyFile, err := os.Create("public_key.pem")
	if err != nil {
		return err
	}
	defer publicKeyFile.Close()

	publicKeyPEM := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(publicKey),
	}

	if err := pem.Encode(publicKeyFile, publicKeyPEM); err != nil {
		return err
	}

	return nil
}

func main() {
	err := generateRSAKeyPair()
	if err != nil {
		panic(err)
	}
}
