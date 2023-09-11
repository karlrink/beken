package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
)

func encryptString(publicKeyFile string, plaintext string) ([]byte, error) {
	// Load the public key from the PEM file
	pubKeyPEM, err := ioutil.ReadFile(publicKeyFile)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(pubKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the public key")
	}

	pubKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	// Encrypt the plaintext with the public key
	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, pubKey, []byte(plaintext))
	if err != nil {
		return nil, err
	}

	return ciphertext, nil
}

func main() {
	publicKeyFile := "public_key.pem"
	plaintext := "Hello GoLang PublicKey Encryption"

	ciphertext, err := encryptString(publicKeyFile, plaintext)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Encrypted Text: %x\n", ciphertext)
}
