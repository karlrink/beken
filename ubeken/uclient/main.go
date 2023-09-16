package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

var version = "1.0.0.🍁-2023-09-15 2"

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

	hexCipher, hexNonce, err := encrypt(keyStr, key)
	if err != nil {
		fmt.Println("Error encrypt:", err)
		return
	}

	//dataStr := name + " " + string(hexCipher) + " " + string(hexNonce)

	base64Cipher := base64.StdEncoding.EncodeToString(hexCipher)
	base64Nonce := base64.StdEncoding.EncodeToString(hexNonce)

	dataStr := name + " " + base64Cipher + " " + base64Nonce

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

	// Decode base64 ciphertext, nonce
	decodedCiphertext, err := base64.StdEncoding.DecodeString(field2)
	if err != nil {
		fmt.Println(err)
		return
	}

	decodedNonce, err := base64.StdEncoding.DecodeString(field3)
	if err != nil {
		fmt.Println(err)
		return
	}

	// Convert decodedCiphertext and decodedNonce to strings
	//ciphertextStr := string(decodedCiphertext)
	//nonceStr := string(decodedNonce)

	// Convert decodedCiphertext and decodedNonce to hexadecimal strings
	ciphertextHex := hex.EncodeToString(decodedCiphertext)
	nonceHex := hex.EncodeToString(decodedNonce)

	decrypted, err := decrypt(ciphertextHex, nonceHex, []byte(key))
	if err != nil {
		log.Println("Error decrypt:", err)
		return
	}

	//fmt.Println("Decrypted:  ", decrypted)

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

func encrypt(plaintext string, key []byte) ([]byte, []byte, error) {

	// Generate a random nonce. The nonce must be unique for each encryption operation.
	// It should never be reused with the same key.
	nonce := make([]byte, chacha20poly1305.NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}

	// Create a new ChaCha20-Poly1305 AEAD cipher instance using the secret key.
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, nil, err
	}

	// Convert the plaintext string to []byte.
	plaintextBytes := []byte(plaintext)

	// Encrypt the plaintext using ChaCha20-Poly1305.
	ciphertext := aead.Seal(nil, nonce, plaintextBytes, nil)

	// Return the ciphertext and nonce as []byte.
	return ciphertext, nonce, nil
}

func decrypt(ciphertextHex string, nonceHex string, key []byte) (string, error) {

	// Parse the hexadecimal strings for ciphertext and nonce.
	ciphertext, err := hex.DecodeString(ciphertextHex)
	if err != nil {
		//log.Fatalf("Failed to decode ciphertext: %v", err)
		return "", err
	}
	if len(ciphertext) == 0 {
		//log.Fatal("Ciphertext cannot be empty")
		return "", err
	}

	nonce, err := hex.DecodeString(nonceHex)
	if err != nil {
		//log.Fatalf("Failed to decode nonce: %v", err)
		return "", err
	}
	if len(nonce) != chacha20poly1305.NonceSize {
		//log.Fatalf("Nonce must be exactly 12 bytes long")
		return "", err
	}

	// Print the nonce and ciphertext as hexadecimal strings.
	fmt.Printf("Nonce: %x\n", nonce)
	fmt.Printf("Ciphertext: %x\n", ciphertext)

	// Define your secret key. In practice, you should generate a strong secret key.
	// Do not use this key for anything sensitive.
	//secretKey := []byte("0123456789abcdef0123456789abcdef")

	// Create a new ChaCha20-Poly1305 AEAD cipher instance using the secret key.
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		//log.Fatalf("Failed to create AEAD cipher: %v", err)
		return "", err
	}

	// Decrypt the ciphertext (for demonstration purposes).
	decrypted, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		//log.Fatalf("Decryption error: %v", err)
		return "", err
	}

	// Print the decrypted plaintext.
	fmt.Printf("Decrypted: %s\n", decrypted)

	return string(decrypted), nil
}

/*


 */
