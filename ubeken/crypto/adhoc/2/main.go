package main

import (
	"crypto/rand"
	"fmt"
	"io"
)

func generateRandomIV(length int) ([]byte, error) {
	iv := make([]byte, length)
	_, err := io.ReadFull(rand.Reader, iv)
	return iv, err
}

func customEncrypt(data []byte, key []byte) ([]byte, []byte, error) {
	// Generate a random IV
	iv, err := generateRandomIV(16)
	if err != nil {
		return nil, nil, err
	}

	// XOR the data with the key
	encryptedData := make([]byte, len(data))
	for i := 0; i < len(data); i++ {
		encryptedData[i] = data[i] ^ key[i%len(key)]
	}

	// XOR the IV with the key and append it to the encrypted data
	ivXORKey := make([]byte, len(key))
	for i := 0; i < len(key); i++ {
		ivXORKey[i] = iv[i%len(iv)] ^ key[i]
	}
	encryptedData = append(ivXORKey, encryptedData...)

	return encryptedData, iv, nil
}

func customDecrypt(encryptedData []byte, key []byte) ([]byte, error) {
	if len(encryptedData) < 16 {
		return nil, fmt.Errorf("invalid encrypted data")
	}

	// Extract the IV by XORing it with the key
	ivXORKey := encryptedData[:len(key)]
	iv := make([]byte, len(ivXORKey))
	for i := 0; i < len(key); i++ {
		iv[i] = ivXORKey[i] ^ key[i]
	}

	// Decrypt the remaining data by XORing it with the key
	decryptedData := make([]byte, len(encryptedData)-len(key))
	for i := 0; i < len(decryptedData); i++ {
		decryptedData[i] = encryptedData[i+len(key)] ^ key[i%len(key)]
	}

	return decryptedData, nil
}

func main() {
	// Sample data to encrypt
	plaintext := []byte("Hello, World!")

	// Encryption key (should be kept secret)
	key := []byte("KEY1234567890")

	// Encrypt the data
	encryptedData, iv, err := customEncrypt(plaintext, key)
	if err != nil {
		fmt.Println("Error encrypting data:", err)
		return
	}

	fmt.Println("Original Data:", string(plaintext))
	fmt.Println("Encrypted Data:", encryptedData)

	// Decrypt the data
	decryptedData, err := customDecrypt(encryptedData, key)
	if err != nil {
		fmt.Println("Error decrypting data:", err)
		return
	}

	fmt.Println("Decrypted Data:", string(decryptedData))
}
