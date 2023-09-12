package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
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

	//data := []byte("my udpXdata")
	//dataStr := "x " + ciphertextStr

	plaintext := "Beken " + time.Now().Format("2006-01-02 15:04:05")

	key := []byte("0123456789ABCDEF0123456789ABCDEF") // 32 bytes for AES-256
	name := "x_user"

	base64cipher, base64Nonce := encrypt(plaintext, key)

	dataStr := name + " " + base64cipher + " " + base64Nonce

	fmt.Println("dataStr: " + dataStr)

	data := []byte(dataStr)

	// Calculate the number of bytes in the byte slice
	byteCount := len(data)

	fmt.Printf("Size of the string in bytes: %d\n", byteCount)

	// Check if the string is greater than 64KB (64 * 1024 bytes)
	if byteCount > 64*1024 {
		fmt.Println("The string is greater than 64KB.")
	}

	_, err = conn.Write(data)
	if err != nil {
		fmt.Println("Error sending UDP packet:", err)
		return
	}

	fmt.Println("Custom UDP packet sent to", destination)

	// Set a timeout for the read operation
	//timeout := 5 * time.Second
	timeout := 1 * time.Second
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

// func encrypt(plaintext string, key []byte) (string, []byte) {
func encrypt(plaintext string, key []byte) (string, string) {
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

	base64Cipher := base64.StdEncoding.EncodeToString(ciphertext)
	base64Nonce := base64.StdEncoding.EncodeToString(nonce)
	return base64Cipher, base64Nonce
}
