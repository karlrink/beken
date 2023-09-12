package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
)

func main() {
	// User1's public key (shared with others)
	// In practice, you would load this from a file or a secure source.
	//var publicKey *rsa.PublicKey

	publicKeyFilePath := "public_key.pem" // Replace with the actual path to your public key file

	// Load the public key from the PEM file
	publicKey, err := loadPublicKeyFromPEMFile(publicKeyFilePath)
	if err != nil {
		fmt.Println("Error loading public key:", err)
		os.Exit(1)
	}

	// Now 'publicKey' contains the loaded public key, which can be used for verification
	fmt.Println("Loaded public key:", publicKey)

	// Accept the received signature as a hexadecimal string from command line argument
	receivedSignatureHex := os.Args[1]

	// Convert the received hexadecimal string back to bytes
	receivedSignature, err := hex.DecodeString(receivedSignatureHex)
	if err != nil {
		fmt.Println("Error decoding received signature:", err)
		os.Exit(1)
	}

	// Received data and signature
	//receivedData := []byte("Hello, this is some important data.")
	receivedData := []byte("Beken Encrypted Data.")
	//receivedSignature := []byte{} // Replace with the actual received signature

	// Calculate the hash of the received data
	hashed := sha256.Sum256(receivedData)

	// Verify the digital signature
	verr := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashed[:], receivedSignature)
	if verr == nil {
		fmt.Println("Signature is valid. Data is trusted.")
	} else {
		fmt.Println("Signature is invalid. Data may be tampered with.")
	}
}

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
