package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
)

func main() {
	// Read the private key from the PEM file
	privateKeyPEM, err := ioutil.ReadFile("private_key.pem")
	if err != nil {
		fmt.Println("Error reading private key file:", err)
		return
	}

	// Decode the PEM-encoded private key
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		fmt.Println("Invalid private key file")
		return
	}

	// Parse the RSA private key
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		fmt.Println("Error parsing private key:", err)
		return
	}

	// Data to be signed
	data := []byte("Hello Golang Encryption")

	// Hash the data
	hashed := sha256.Sum256(data)

	// Sign the hashed data using the private key
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed[:])
	if err != nil {
		fmt.Println("Error signing data:", err)
		return
	}

	fmt.Printf("Original Data: %s\n", data)
	fmt.Printf("Signature: %x\n", signature)
}
