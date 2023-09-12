package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io/ioutil"
)

func main() {
	// Read the public key from the PEM file
	publicKeyPEM, err := ioutil.ReadFile("public_key.pem")
	if err != nil {
		fmt.Println("Error reading public key file:", err)
		return
	}

	// Decode the PEM-encoded public key
	block, _ := pem.Decode(publicKeyPEM)
	if block == nil || block.Type != "PUBLIC KEY" {
		fmt.Println("Invalid public key file")
		return
	}

	// Parse the RSA public key
	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		fmt.Println("Error parsing public key:", err)
		return
	}

	// Data that was signed
	//data := []byte("Hello Golang Encryption")
	// Hash the data
	//hashed := sha256.Sum256(data)

	// Signature (to be verified)
	signatureBytes, err := hex.DecodeString("...") // Replace with the actual signature bytes
	if err != nil {
		fmt.Println("Error decoding signature:", err)
		return
	}

	// Verify the signature using the public key
	err = rsa.VerifyPKCS1v15(publicKey.(*rsa.PublicKey), crypto.SHA256, hashed[:], signatureBytes)
	if err == nil {
		fmt.Println("Signature is valid")
	} else {
		fmt.Println("Signature is invalid:", err)
	}
}
