package main

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
)

func main() {
	// Check if sufficient arguments are provided
	if len(os.Args) < 3 {
		fmt.Println("Usage: go run main.go <yourUsername> <yourPassword>")
		return
	}

	// Read username and password from command line arguments
	user := os.Args[1]
	pass := os.Args[2]

	// Concatenate the username and password with a colon
	data := user + ":" + pass

	// Compute SHA-256 hash
	hash := sha256.New()
	hash.Write([]byte(data))
	hashedData := hash.Sum(nil)

	// Perform Base64 encoding
	base64Encoded := base64.StdEncoding.EncodeToString(hashedData)

	// Print the hashed and encoded data
	//fmt.Println("SHA-256 Hash:", hashedData)
	fmt.Println("Base64 Encoded:", base64Encoded)
}
