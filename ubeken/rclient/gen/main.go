package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

func main() {
	// Generate a new RSA private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Println("Failed to generate private key:", err)
		return
	}

	// Encode the private key in PEM format
	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}

	// Write the private key to a file (e.g., private.pem)
	privateFile, err := os.Create("private.pem")
	if err != nil {
		fmt.Println("Failed to create private key file:", err)
		return
	}
	defer privateFile.Close()
	err = pem.Encode(privateFile, privateKeyPEM)
	if err != nil {
		fmt.Println("Failed to write private key to file:", err)
		return
	}
	fmt.Println("Private key generated and saved to private.pem")

	// Extract the public key from the private key
	publicKey := &privateKey.PublicKey

	// Encode the public key in PEM format
	publicKeyPEM := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(publicKey),
	}

	// Write the public key to a file (e.g., public.pem)
	publicFile, err := os.Create("public.pem")
	if err != nil {
		fmt.Println("Failed to create public key file:", err)
		return
	}
	defer publicFile.Close()
	err = pem.Encode(publicFile, publicKeyPEM)
	if err != nil {
		fmt.Println("Failed to write public key to file:", err)
		return
	}
	fmt.Println("Public key generated and saved to public.pem")
}
