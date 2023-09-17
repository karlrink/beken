package main

import (
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
	//"github.com/aead/chacha20poly1305"
)

func main() {

	if len(os.Args) != 4 {
		fmt.Println("Usage: main <base64Ciphertext> <base64Nonce> <key>")
		os.Exit(1)
	}

	// Base64-encoded ciphertext and nonce received from Swift
	//swiftCipherText := "YOUR_BASE64_CIPHER_TEXT"
	//swiftNonce := "YOUR_BASE64_NONCE"
	swiftCipherText := os.Args[1]
	swiftNonce := os.Args[2]
	//keyStr := os.Args[3]

	keyStr := strings.TrimSpace(os.Args[3])

	// Base64-decode ciphertext and nonce
	cipherText, err := base64.StdEncoding.DecodeString(swiftCipherText)
	if err != nil {
		log.Fatalf("Error decoding ciphertext: %v", err)
	}

	nonce, err := base64.StdEncoding.DecodeString(swiftNonce)
	if err != nil {
		log.Fatalf("Error decoding nonce: %v", err)
	}

	// Convert the keyStr to the actual encryption key
	//keyStr := "YOUR_KEY_STR"
	key := []byte(keyStr) // Make sure it matches the key used in Swift

	// Create a ChaCha20-Poly1305 cipher
	cipher, err := chacha20poly1305.New(key)
	if err != nil {
		log.Fatalf("Error creating ChaCha20-Poly1305 cipher: %v", err)
	}

	// Decrypt the data
	decryptedData, err := cipher.Open(nil, nonce, cipherText, nil)
	if err != nil {
		log.Fatalf("Error decrypting data: %v", err)
	}

	// Print the decrypted message
	decryptedMessage := string(decryptedData)
	fmt.Println("Decrypted Message:", decryptedMessage)
}
