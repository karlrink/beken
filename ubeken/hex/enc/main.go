package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
)

func main() {

	if len(os.Args) != 3 {
		fmt.Println("Usage: main <key> plaintext")
		os.Exit(1)
	}

	//key := []byte(os.Args[1])
	key := []byte(strings.Replace(strings.TrimSpace(os.Args[1]), "\n", "", -1))
	plaintext := os.Args[2]

	hexCipher, hexNonce, hexTag, err := encrypt(plaintext, key)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(2)
	}

	fmt.Println("Encrypted:", hexCipher, hexNonce, hexTag)
}

func encrypt(plaintext string, key []byte) (string, string, string, error) {

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", "", "", err
	}

	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", "", "", err
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", "", "", err
	}

	ciphertext := aead.Seal(nil, nonce, []byte(plaintext), nil)

	hexCipher := hex.EncodeToString(ciphertext)
	hexNonce := hex.EncodeToString(nonce)
	hexTag := hex.EncodeToString(aead.Seal(nil, nonce, nil, ciphertext))

	return hexCipher, hexNonce, hexTag, nil
}
