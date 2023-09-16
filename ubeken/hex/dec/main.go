package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

func main() {

	if len(os.Args) != 5 {
		fmt.Println("Usage: main <hexCiphertext> <hexNonce> <hexTag> <key>")
		os.Exit(1)
	}

	ciphertext := os.Args[1]
	nonce := os.Args[2]
	tag := os.Args[3]
	//key := []byte(os.Args[4])
	key := []byte(strings.Replace(strings.TrimSpace(os.Args[4]), "\n", "", -1))

	decodedCiphertext, err := hex.DecodeString(ciphertext)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	decodedNonce, err := hex.DecodeString(nonce)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	decodedTag, err := hex.DecodeString(tag)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	decryptedPlaintext, err := aead.Open(nil, decodedNonce, decodedCiphertext, decodedTag)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Println(string(decryptedPlaintext))
}
