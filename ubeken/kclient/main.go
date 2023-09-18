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
	"strings"
	"time"
)

var version = "1.0.0.🍁-2023-09-18"

func main() {
	if len(os.Args) < 4 {
		fmt.Println("Usage: " + os.Args[0] + " name symmetric.key localhost:9480")
		return
	}

	name := os.Args[1]
	//keyStr := os.Args[2] //12345678901234567890123456789012
	keyFile := os.Args[2]
	destination := os.Args[3]

	keyStr, err := readKeyFromFile(keyFile)
	if err != nil {
		fmt.Println("Error reading key from file:", err)
		return
	}

	plaintext := "Beken " + time.Now().Format("2006-01-02 15:04:05")

	base64Cipher, base64Nonce, base64Tag, err := encryptAES(plaintext, keyStr)
	if err != nil {
		fmt.Println("Error encrypt:", err)
		return
	}

	dataStr := name + " 3 " + base64Cipher + " " + base64Nonce + " " + base64Tag

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

func encryptKES(plaintext, keyStr string) (string, string, error) {

	key := []byte(keyStr)

	// Generate a random nonce
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", "", "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", "", "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", "", "", err
	}

	plaintextBytes := []byte(plaintext)
	ciphertext := aesGCM.Seal(nil, nonce, plaintextBytes, nil)

	ciphertextBase64 := base64.StdEncoding.EncodeToString(ciphertext)
	nonceBase64 := base64.StdEncoding.EncodeToString(nonce)
	tagBase64 := base64.StdEncoding.EncodeToString(aesGCM.Seal(nil, nonce, nil, nil))

	return ciphertextBase64, nonceBase64, nil
}

func readKeyFromFile(keyFile string) (string, error) {
	keyBytes, err := os.ReadFile(keyFile)
	if err != nil {
		return "", err
	}

	// Trim any newline characters (e.g., '\n', '\r\n') from the end of the key
	keyStr := strings.TrimRight(string(keyBytes), "\r\n")

	return keyStr, nil
}

/*


 */
