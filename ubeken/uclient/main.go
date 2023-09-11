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

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Usage: client <server_address>")
		return
	}

	destination := os.Args[1]

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

	publicKeyFile := "public_key.pem"
	plaintext := "Hello GoLang PublicKey Encryption"

	ciphertext, err := encryptString(publicKeyFile, plaintext)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Encrypted Text: %x\n", ciphertext)

	// Encode the ciphertext as base64 and create a string
	ciphertextStr := base64.StdEncoding.EncodeToString(ciphertext)

	fmt.Printf("Base64 Text: %x\n", ciphertextStr)
	//data := []byte("my udpXdata")

	// Encode the string to base64
	//base64String := base64.StdEncoding.EncodeToString([]byte(ciphertext))
	//fmt.Printf("Encoded: %s\n", base64String)

	//dataStr := "x " + base64String

	dataStr := "x " + ciphertextStr

	data := []byte(dataStr)

	_, err = conn.Write(data)
	if err != nil {
		fmt.Println("Error sending UDP packet:", err)
		return
	}

	fmt.Println("Custom UDP packet sent to", destination)

	// Set a timeout for the read operation
	timeout := 5 * time.Second
	conn.SetReadDeadline(time.Now().Add(timeout))

	buffer := make([]byte, 1024)

	n, _, err := conn.ReadFromUDP(buffer)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			fmt.Println("Server did not respond within the timeout.")
			return
		}
		fmt.Println("Error receiving UDP response:", err)
		return
	}

	response := string(buffer[:n])
	fmt.Println("Received UDP response:", response)
}

func encryptString(publicKeyFile string, plaintext string) ([]byte, error) {
	// Load the public key from the PEM file
	pubKeyPEM, err := ioutil.ReadFile(publicKeyFile)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(pubKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the public key")
	}

	pubKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	// Encrypt the plaintext with the public key
	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, pubKey, []byte(plaintext))
	if err != nil {
		return nil, err
	}

	return ciphertext, nil
}
