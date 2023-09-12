package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
)

func main() {
	plaintext := "This is important data"
	key := []byte("0123456789ABCDEF0123456789ABCDEF") // 32 bytes for AES-256
	ciphertext, nonce := encrypt(plaintext, key)
	decrypted := decrypt(ciphertext, nonce, key)

	fmt.Println("Original:   ", plaintext)
	fmt.Println("Ciphertext: ", ciphertext)
	fmt.Println("Decrypted:  ", decrypted)
}

func encrypt(plaintext string, key []byte) (string, []byte) {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	ciphertext := aead.Seal(nil, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nonce
}

func decrypt(ciphertext string, nonce, key []byte) string {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	decodedCiphertext, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		panic(err.Error())
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	plaintext, err := aead.Open(nil, nonce, decodedCiphertext, nil)
	if err != nil {
		panic(err.Error())
	}

	return string(plaintext)
}
