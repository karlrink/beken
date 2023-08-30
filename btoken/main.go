package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"
)

func main() {
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
}
