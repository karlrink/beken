package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) != 4 {
		fmt.Println("Usage: main <base64Ciphertext> <base64Nonce> <key>")
		os.Exit(1)
	}

	base64Ciphertext := os.Args[1]
	base64Nonce := os.Args[2]
	key := []byte(os.Args[3])

	plaintext, err := decrypt(base64Ciphertext, base64Nonce, key)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(2)
	}

	fmt.Println("Decrypted plaintext:", plaintext)
}

func decrypt(base64Ciphertext string, base64Nonce string, key []byte) (string, error) {

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	decodedCiphertext, err := base64.StdEncoding.DecodeString(base64Ciphertext)
	if err != nil {
		return "", err
	}

	decodedNonce, err := base64.StdEncoding.DecodeString(base64Nonce)
	if err != nil {
		return "", err
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	plaintext, err := aead.Open(nil, decodedNonce, decodedCiphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}
