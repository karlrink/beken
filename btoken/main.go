package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

func main() {
	//bekenUser := "someUser"
	//newBekenPass := "somePassword"

	// Generate beken_token similar to "bt-" + base64(SHA-256(beken_user + ":" + new_beken_pass))
	//sha256Hash := sha256.Sum256([]byte(bekenUser + ":" + newBekenPass))
	//sha256HashBase64 := base64.StdEncoding.EncodeToString(sha256Hash[:])
	//bekenToken := "bt-" + sha256HashBase64
	//fmt.Println("beken_token:", bekenToken)

	reader := bufio.NewReader(os.Stdin)

	// Get username
	fmt.Print("Enter username: ")
	bekenUser, _ := reader.ReadString('\n')
	bekenUser = strings.TrimSpace(bekenUser)

	// Get password without echoing it
	fmt.Print("Enter password: ")
	passwordBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		fmt.Println("\nError reading password:", err)
		return
	}
	newBekenPass := string(passwordBytes)
	fmt.Println() // Newline for better formatting

	// Generate token
	text := bekenUser + ":" + newBekenPass
	data := []byte(text)
	hasher := sha256.New()
	hasher.Write(data)
	hashedData := hasher.Sum(nil)

	// Base64 encode
	base64Encoded := base64.StdEncoding.EncodeToString(hashedData)

	// Prepend "bt-" to base64 encoded string
	bekenToken := "bt-" + base64Encoded

	fmt.Println("Generated beken_token:", bekenToken)

	// Generate AES-GCM encryption key (for demonstration using a 16 byte key)
	//key := []byte("1234567890123456") // This is just an example key; you'll want to replace it

	// Generate a random 32-byte key for AES-256
	//key := make([]byte, 32)
	//if _, err := io.ReadFull(rand.Reader, key); err != nil {
	//	panic(err.Error())
	//}

	key_random16, err := randomString(16)
	if err != nil {
		fmt.Printf("Failed to generate random: %v\n", err)
		return
	}

	// Convert string to []byte
	key_random16Bytes := []byte(key_random16)

	//iv, ciphertext := aesEncrypt([]byte(newBekenPass), key)
	iv, ciphertext := aesEncrypt([]byte(newBekenPass), key_random16Bytes)
	ivBase64 := base64.StdEncoding.EncodeToString(iv)
	ciphertextBase64 := base64.StdEncoding.EncodeToString(ciphertext)
	fmt.Println("Encrypted data:", ciphertextBase64+" "+ivBase64)
	fmt.Println("Key:", key_random16)
}

// aesEncrypt encrypts plaintext using AES-GCM mode with a given key.
// It returns the IV and the ciphertext.
func aesEncrypt(plaintext, key []byte) ([]byte, []byte) {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	// Generate a random IV of 12 bytes
	iv := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err.Error())
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	ciphertext := aesgcm.Seal(nil, iv, plaintext, nil)
	return iv, ciphertext
}

func randomString(length int) (string, error) {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}
