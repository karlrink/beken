package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
)

func main() {

	// Get the encrypted message from the SwiftUI code.
	//encryptedMessage := "base64Cipher base64Nonce base64Tag" // Include the tag in the string
	// Split the encrypted message into the three components: ciphertext, nonce, and tag.
	//components := encryptedMessage.Split(" ")
	//ciphertext := components[0]
	//nonce := components[1]
	//tag := components[2]

	if len(os.Args) != 5 {
		fmt.Println("Usage: main <base64Ciphertext> <base64Nonce> <base64Tag> <key>")
		os.Exit(1)
	}

	ciphertext := strings.Replace(strings.TrimSpace(os.Args[1]), "\n", "", -1)
	nonce := strings.Replace(strings.TrimSpace(os.Args[2]), "\n", "", -1)
	tag := strings.Replace(strings.TrimSpace(os.Args[3]), "\n", "", -1)

	key := []byte(strings.Replace(strings.TrimSpace(os.Args[4]), "\n", "", -1))

	// Decode the ciphertext, nonce, and tag.
	decodedCiphertext, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	decodedNonce, err := base64.StdEncoding.DecodeString(nonce)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	decodedTag, err := base64.StdEncoding.DecodeString(tag)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// Create a new AES cipher.
	//block, err := aes.NewCipher([]byte("secret-key"))
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// Create a new GCM authenticated encryption algorithm.
	aead, err := cipher.NewGCM(block)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// Decrypt the data.
	decryptedPlaintext, err := aead.Open(nil, decodedNonce, decodedCiphertext, decodedTag)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// Print the decrypted plaintext.
	fmt.Println(string(decryptedPlaintext))
}
