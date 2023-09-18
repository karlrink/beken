package main

import (
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/fernet/fernet-go"
)

var version = "1.0.0.🍁-2023-09-17"

func main() {
	if len(os.Args) < 4 {
		fmt.Println("Usage: " + os.Args[0] + " name key localhost:9480")
		return
	}

	name := os.Args[1]
	keyStr := os.Args[2] //12345678901234567890123456789012
	destination := os.Args[3]

	plaintext := "Beken " + time.Now().Format("2006-01-02 15:04:05")

	base64Cipher, err := encryptFernet(plaintext, keyStr)
	if err != nil {
		fmt.Println("Error encrypt:", err)
		return
	}

	dataStr := name + " 2 " + base64Cipher

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

func encryptFernet(plaintext string, fernetKey string) (string, error) {

	// Encode the key as a base64 string
	base64Key := base64.StdEncoding.EncodeToString([]byte(fernetKey))
	//fmt.Println("base64 key: " + base64Key)
	//k := fernet.MustDecodeKeys("cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=")
	k := fernet.MustDecodeKeys(base64Key)

	tok, err := fernet.EncryptAndSign([]byte(plaintext), k[0])
	if err != nil {
		panic(err)
	}

	//fmt.Println(tok)
	base64Cipher := base64.StdEncoding.EncodeToString([]byte(tok))
	//fmt.Println("base64 Encrypted: " + base64Cipher)

	// Return the base64 ciphertext
	return base64Cipher, nil
}

/*


 */
