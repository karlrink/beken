package main

import (
	"crypto/rand"
	"fmt"
	"io"
	"log"

	"golang.org/x/crypto/chacha20poly1305"
)

func main() {
	// Define your secret key. In practice, you should generate a strong secret key.
	// Do not use this key for anything sensitive.
	secretKey := []byte("0123456789abcdef0123456789abcdef")

	// Define the plaintext message to encrypt.
	plaintext := []byte("Hello ChaCha Encryption")

	// Generate a random nonce. The nonce must be unique for each encryption operation.
	// It should never be reused with the same key.
	nonce := make([]byte, chacha20poly1305.NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		log.Fatalf("Failed to generate nonce: %v", err)
	}

	// Create a new ChaCha20-Poly1305 AEAD cipher instance using the secret key.
	aead, err := chacha20poly1305.New(secretKey)
	if err != nil {
		log.Fatalf("Failed to create AEAD cipher: %v", err)
	}

	// Encrypt the plaintext using ChaCha20-Poly1305.
	ciphertext := aead.Seal(nil, nonce, plaintext, nil)

	// Print the nonce and ciphertext as hexadecimal strings.
	fmt.Printf("Ciphertext: %x\n", ciphertext)
	fmt.Printf("Nonce: %x\n", nonce)

}
