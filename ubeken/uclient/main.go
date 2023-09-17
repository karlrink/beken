package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"time"
)

var version = "1.0.0.🍁-2023-09-17"

func main() {
	if len(os.Args) < 4 {
		fmt.Println("Usage: " + os.Args[0] + " name public.pem localhost:9480")
		return
	}

	name := os.Args[1]
	publicKey := os.Args[2] //public.pem
	destination := os.Args[3]

	// Load the RSA public key from the public key file.
	loadedPublicKey, err := loadPublicKey(publicKey)
	if err != nil {
		fmt.Println("Error loading public key:", err)
		return
	}

	plaintext := "Beken packet"

	base64Cipher, err := encrypt(plaintext, loadedPublicKey)
	if err != nil {
		fmt.Println("Error encrypt:", err)
		return
	}

	dataStr := name + " " + base64Cipher

	fmt.Println("base64 Cipher: " + dataStr)

	data := []byte(dataStr)

	// Calculate the number of bytes in the byte slice
	byteCount := len(data)

	fmt.Printf("Size of the string in bytes: %d\n", byteCount)

	// Check if the string is greater than 64KB (64 * 1024 bytes)
	if byteCount > 64*1024 {
		fmt.Println("The string is greater than 64KB.")
	}

	udpAddr, err := net.ResolveUDPAddr("udp", destination)
	if err != nil {
		fmt.Println("Error resolving UDP address:", err)
		return
	}

	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		fmt.Println("Error creating UDP connection:", err)
		return
	}
	defer conn.Close()

	_, err = conn.Write(data)
	if err != nil {
		fmt.Println("Error sending UDP packet:", err)
		return
	}

	fmt.Println("Custom UDP packet sent to", destination)

	// Set a timeout for the read operation
	//timeout := 5 * time.Second
	timeout := 3 * time.Second
	conn.SetReadDeadline(time.Now().Add(timeout))

	buffer := make([]byte, 1024)

	n, _, err := conn.ReadFromUDP(buffer)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			fmt.Println("Server did not respond within the timeout.")
			return
		}
		fmt.Println("Error receiving UDP response:", err)
		//fmt.Println("Bummer. dycrypt packet lost.")
		return
	}

	response := string(buffer[:n])
	fmt.Println("Received UDP response:", response)

}

func encrypt(plaintext string, publicKey *rsa.PublicKey) (string, error) {

	// Encrypt the plaintext using the public key.
	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, []byte(plaintext))
	if err != nil {
		fmt.Println("Error encrypting:", err)
		return "", err
	}

	// Encode to Base64
	base64Cipher := base64.StdEncoding.EncodeToString(ciphertext)

	// Return the base64 ciphertext
	return base64Cipher, nil
}

func loadPublicKey(publicKeyFile string) (*rsa.PublicKey, error) {

	// Read the public key file.
	publicKeyData, err := ioutil.ReadFile(publicKeyFile)
	if err != nil {
		return nil, err
	}

	// Parse the public key PEM block.
	block, _ := pem.Decode(publicKeyData)
	if block == nil {
		return nil, fmt.Errorf("failed to parse public key PEM")
	}

	// Check the type of the decoded block.
	if block.Type != "RSA PUBLIC KEY" {
		return nil, fmt.Errorf("unexpected public key type: %s", block.Type)
	}

	// Parse the public key as an RSA public key.
	rsaPublicKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return rsaPublicKey, nil
}

/*


 */
