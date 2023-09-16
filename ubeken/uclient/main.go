package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strings"
	"time"
)

var version = "1.0.0.🍁-2023-09-15 1"

func main() {
	if len(os.Args) < 4 {
		fmt.Println("Usage: " + os.Args[0] + " name key_file localhost:9480")
		return
	}

	name := os.Args[1]
	keyFile := os.Args[2]
	destination := os.Args[3]

	// Read the file contents into a variable
	keyBytes, err := ioutil.ReadFile(keyFile)
	if err != nil {
		fmt.Println("Error reading file:", err)
		return
	}

	// Convert the file contents to a string and remove leading/trailing white spaces
	keyStr := strings.TrimSpace(string(keyBytes))

	// Ensure the key is exactly 32 bytes (256 bits) long
	if len(keyStr) != 32 {
		fmt.Println("Invalid key length. Key must be 32 bytes long.")
		return
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

	//key := []byte("0123456789ABCDEF0123456789ABCDEF") // 32 bytes for AES-256
	key := []byte(keyStr) // 32 bytes for AES-256

	base64cipher, base64Nonce, base64Tag, err := encrypt(keyStr, key)
	if err != nil {
		fmt.Println("Error encrypt:", err)
		return
	}

	dataStr := name + " " + base64cipher + " " + base64Nonce + " " + base64Tag

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

	// decrypt

	str := strings.Split(response, " ")
	//field1 := str[0] //name
	field2 := str[1] //cypher
	field3 := str[2] //nonce
	//field4 := str[3] //tag

	//decrypted, err := decrypt(field2, field3, field4, key)
	decrypted, err := decrypt(field2, field3, []byte(key))
	if err != nil {
		log.Println("Error decrypt:", err)
		return
	}

	fmt.Println("Decrypted:  ", decrypted)

	// write new key

	// Open the file for writing. Create it if it doesn't exist, or truncate it if it does.
	file, err := os.Create(keyFile)
	if err != nil {
		fmt.Println("Error creating file:", err)
		return
	}
	defer file.Close()

	// Write the string to the file
	_, err = file.WriteString(decrypted)
	if err != nil {
		fmt.Println("Error writing to file:", err)
		return
	}

	fmt.Println("wrote new key")

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

/*


 */
