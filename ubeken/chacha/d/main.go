package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"os"

	"golang.org/x/crypto/chacha20poly1305"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Println("Usage: ./program ciphertext nonce")
		return
	}

	ciphertextHex := os.Args[1]
	nonceHex := os.Args[2]

	// Parse the hexadecimal strings for ciphertext and nonce.
	ciphertext, err := hex.DecodeString(ciphertextHex)
	if err != nil {
		log.Fatalf("Failed to decode ciphertext: %v", err)
	}
	if len(ciphertext) == 0 {
		log.Fatal("Ciphertext cannot be empty")
	}

	nonce, err := hex.DecodeString(nonceHex)
	if err != nil {
		log.Fatalf("Failed to decode nonce: %v", err)
	}
	if len(nonce) != chacha20poly1305.NonceSize {
		log.Fatalf("Nonce must be exactly 12 bytes long")
	}

	// Print the nonce and ciphertext as hexadecimal strings.
	fmt.Printf("Nonce: %x\n", nonce)
	fmt.Printf("Ciphertext: %x\n", ciphertext)

	// Define your secret key. In practice, you should generate a strong secret key.
	// Do not use this key for anything sensitive.
	secretKey := []byte("0123456789abcdef0123456789abcdef")

	// Create a new ChaCha20-Poly1305 AEAD cipher instance using the secret key.
	aead, err := chacha20poly1305.New(secretKey)
	if err != nil {
		log.Fatalf("Failed to create AEAD cipher: %v", err)
	}

	// Decrypt the ciphertext (for demonstration purposes).
	decrypted, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		log.Fatalf("Decryption error: %v", err)
	}

	// Print the decrypted plaintext.
	fmt.Printf("Decrypted: %s\n", decrypted)
}
