package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
)

func decryptCiphertext(privateKeyFile string, ciphertext []byte) (string, error) {
	// Load the private key from the PEM file
	privateKeyPEM, err := ioutil.ReadFile(privateKeyFile)
	if err != nil {
		return "", err
	}

	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		return "", fmt.Errorf("failed to parse PEM block containing the private key")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return "", err
	}

	// Decrypt the ciphertext with the private key
	plaintext, err := rsa.DecryptPKCS1v15(nil, privateKey, ciphertext)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

func main() {
	privateKeyFile := "private_key.pem"
	//ciphertextHex := "your_ciphertext_hex_here" // Replace with the actual ciphertext in hexadecimal format
	ciphertextHex := os.Args[1]

	ciphertext, err := hexToBytes(ciphertextHex)
	if err != nil {
		panic(err)
	}

	plaintext, err := decryptCiphertext(privateKeyFile, ciphertext)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Decrypted Text: %s\n", plaintext)
}

func hexToBytes(hex string) ([]byte, error) {
	// Remove spaces and convert hex string to bytes
	hex = filterHex(hex)
	hexLen := len(hex)
	if hexLen%2 != 0 {
		return nil, fmt.Errorf("hex string length must be even")
	}
	bytes := make([]byte, hexLen/2)
	for i := 0; i < hexLen; i += 2 {
		if _, err := fmt.Sscanf(hex[i:i+2], "%02x", &bytes[i/2]); err != nil {
			return nil, err
		}
	}
	return bytes, nil
}

func filterHex(hex string) string {
	filteredHex := ""
	for _, char := range hex {
		if (char >= '0' && char <= '9') || (char >= 'a' && char <= 'f') || (char >= 'A' && char <= 'F') {
			filteredHex += string(char)
		}
	}
	return filteredHex
}
