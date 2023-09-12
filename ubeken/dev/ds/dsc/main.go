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
	// Generate a private key (User1's private key)
	//privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)

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
	data := []byte("Hello, this is some important data.")

	// Calculate the hash of the data
	hashed := sha256.Sum256(data)

	// Sign the hashed data with the private key
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed[:])
	if err != nil {
		fmt.Println("Error signing:", err)
		return
	}

	// Now 'signature' contains the digital signature
	fmt.Printf("Digital Signature: %x\n", signature)
}
