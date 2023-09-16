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

	b64ciphertext, b64nonce, b64tag, err := encrypt(plaintext, key)
	if err != nil {
		panic(err)
	}

	fmt.Println("ciphertext:   ", b64ciphertext)
	fmt.Println("nonce:   ", b64nonce)
	fmt.Println("tag:   ", b64tag)

	decrypted, err := decrypt(b64ciphertext, b64nonce, key)
	if err != nil {
		panic(err)
	}

	fmt.Println("Original:   ", plaintext)
	fmt.Println("Ciphertext: ", b64ciphertext)
	fmt.Println("Decrypted:  ", decrypted)
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
	tag := aead.Seal(nil, nonce, nil, ciphertext)

	base64Cipher := base64.StdEncoding.EncodeToString(ciphertext)
	base64Nonce := base64.StdEncoding.EncodeToString(nonce)
	base64Tag := base64.StdEncoding.EncodeToString(tag)

	return base64Cipher, base64Nonce, base64Tag, nil
}

func decrypt(base64Cipher string, base64Nonce string, key []byte) (string, error) {

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	decodedCiphertext, err := base64.StdEncoding.DecodeString(base64Cipher)
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
