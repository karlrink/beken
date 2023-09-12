package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
)

func loadPublicKeyFromPEMFile(publicKeyFilePath string) (*rsa.PublicKey, error) {
	// Read the PEM file containing the public key
	pemData, err := ioutil.ReadFile(publicKeyFilePath)
	if err != nil {
		return nil, err
	}

	// Parse the PEM data
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing public key")
	}

	// Parse the RSA public key
	publicKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return publicKey, nil
}

func main() {
	publicKeyFilePath := "public_key.pem" // Replace with the actual path to your public key file

	// Accept the received signature as a hexadecimal string from command line argument
	if len(os.Args) < 2 {
		fmt.Println("Usage: verify_signature <signature_hex>")
		os.Exit(1)
	}
	receivedSignatureHex := os.Args[1]

	// Convert the received hexadecimal string back to bytes
	receivedSignature, err := hex.DecodeString(receivedSignatureHex)
	if err != nil {
		fmt.Println("Error decoding received signature:", err)
		os.Exit(1)
	}

	// Load the public key from the PEM file
	publicKey, err := loadPublicKeyFromPEMFile(publicKeyFilePath)
	if err != nil {
		fmt.Println("Error loading public key:", err)
		os.Exit(1)
	}

	// Verify the digital signature
	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, []byte("unknown_data"), receivedSignature)
	if err == nil {
		fmt.Println("Signature is valid.")
	} else {
		fmt.Println("Signature is invalid.")
	}
}
