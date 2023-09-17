package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
)

func main() {
	// Generate or load the RSA key pair.
	//privateKey, publicKey, err := generateOrLoadRSAKeyPair("private.pem", "public.pem", 2048)
	_, publicKey, err := generateOrLoadRSAKeyPair("private.pem", "public.pem", 2048)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	//fmt.Println(privateKey)

	// The string to encrypt.
	plaintext := "Hello RSA"

	// Encrypt the plaintext using the public key.
	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, []byte(plaintext))
	if err != nil {
		fmt.Println("Error encrypting:", err)
		return
	}

	fmt.Printf("Encrypted: %x\n", ciphertext)
}

func generateOrLoadRSAKeyPair(privateKeyFile, publicKeyFile string, keySize int) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	// Check if private and public keys exist, and if so, load them.
	privateKey, err := loadPrivateKey(privateKeyFile)
	if err != nil {
		// If the private key doesn't exist, generate a new key pair.
		fmt.Println("Generating RSA key pair...")
		privateKey, err = rsa.GenerateKey(rand.Reader, keySize)
		if err != nil {
			return nil, nil, err
		}

		// Save the private key to a file.
		privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
		privateKeyPEM := pem.Block{
			Type:    "RSA PRIVATE KEY",
			Headers: nil,
			Bytes:   privateKeyBytes,
		}
		err = ioutil.WriteFile(privateKeyFile, pem.EncodeToMemory(&privateKeyPEM), 0644)
		if err != nil {
			return nil, nil, err
		}

		// Save the public key to a file.
		publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
		if err != nil {
			return nil, nil, err
		}
		publicKeyPEM := pem.Block{
			Type:    "RSA PUBLIC KEY",
			Headers: nil,
			Bytes:   publicKeyBytes,
		}
		err = ioutil.WriteFile(publicKeyFile, pem.EncodeToMemory(&publicKeyPEM), 0644)
		if err != nil {
			return nil, nil, err
		}
		fmt.Println("Key pair generated and saved.")
	}

	return privateKey, &privateKey.PublicKey, nil
}

func loadPrivateKey(privateKeyFile string) (*rsa.PrivateKey, error) {
	// Read the private key file.
	privateKeyData, err := ioutil.ReadFile(privateKeyFile)
	if err != nil {
		return nil, err
	}

	// Parse the private key PEM block.
	block, _ := pem.Decode(privateKeyData)
	if block == nil {
		return nil, fmt.Errorf("failed to parse private key PEM")
	}

	// Parse the private key.
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}
