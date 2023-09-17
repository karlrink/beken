package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"

	"database/sql"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/chacha20poly1305"
)

var version = "1.0.0.🍁-2023-09-15 2"

func usage() {

	fmt.Println(`Usage: ` + os.Args[0] + ` </path/db> [port]

  --help|-help|help           Display this help message
  --version|-version|version  Display version

<db> 9480 # Default `)
}

func main() {

	if len(os.Args) < 2 {
		usage()
		return
	}

	switch os.Args[1] {
	case "--help", "-help", "help":
		usage()
		return
	case "--version", "-version", "version":
		fmt.Println("Version: " + version)
		sqlite3version, err := getSqlite3Version(os.Args[1])
		if err != nil {
			log.Fatal("Failed to get SQLite version: %v\n", err)
		}
		fmt.Println("Sqlite3: " + sqlite3version)
		return

	}

	dbFile := os.Args[1]

	var defaultPort = "9480"

	if len(os.Args) > 2 {
		defaultPort = os.Args[2]
	}

	// Define the address to listen on
	address := ":" + defaultPort // ":9480"

	// Configure the log package to write to standard output (os.Stdout).
	log.SetOutput(os.Stdout)

	// Resolve the UDP address
	udpAddr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		log.Fatal("Error resolving UDP address:", err)
	}

	// Create a UDP connection
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Fatal("Error creating UDP connection:", err)
	}
	defer conn.Close()

	//fmt.Println("UDP server listening on " + address)

	// Create a buffer to hold incoming data
	buffer := make([]byte, 1024)

	// Open or create the SQLite3 database
	//db, err := sql.Open("sqlite3", "udp_database.db")
	db, err := sql.Open("sqlite3", dbFile)
	if err != nil {
		log.Fatal("Error opening database:", err)
	}
	defer db.Close()

	create := createTables(db)
	if create != nil {
		log.Fatal("Error creating tables:", create)
	}

	log.Println("UDP server listening on " + address)

	for {
		// Read data from the connection
		n, addr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			log.Println("Error reading from UDP connection:", err)
			continue
		}

		receivedData := string(buffer[:n])

		// Process each packet in a Goroutine
		go func(data string, clientAddr *net.UDPAddr) {

			exists, key, decrypted := existsAndDecrypts(db, data)

			if exists {

				fmt.Println(decrypted)
				fmt.Println("Data exists and decrypts:", data)

				str := strings.Split(data, " ")
				field1 := str[0] //name
				//field2 := str[1] //cypher
				//field3 := str[2] //nonce

				// Add clientAddr to db
				// Convert clientAddr to a string
				clientAddrStr := clientAddr.String()

				// Remove the port from the IP address
				host, _, err := net.SplitHostPort(clientAddrStr) // works for IPv4 and IPv6 addresses
				if err != nil {
					log.Printf("Failed to split host and port: %v\n", err)
				}

				// Save the IP to the database
				_, err = db.Exec("INSERT INTO ips (Name, Data) VALUES (?, ?)", host, field1)
				if err != nil {
					log.Printf("Failed to save IP to database: %v\n", err)
				} else {
					log.Printf("Isert IP %s \n", host)
				}

				// Issue new key (replaces old)
				new_key, err := issueNewKey(db, field1)
				if err != nil {
					log.Printf("Failed issue new key database: %v\n", err)
				}
				//fmt.Println("new_key: " + new_key)

				// encrypt

				hexCipher, hexNonce, err := encrypt(new_key, []byte(key))
				if err != nil {
					log.Printf("Failed encrypt: %v\n", err)
				}
				//fmt.Println("base64cipher: " + base64cipher + " base64Nonce: " + base64Nonce)

				// Send a response back to the client
				//response := "your udp received"

				//response := field1 + " " + hexCipher + " " + hexNonce
				//response := field1 + " " + string(hexCipher) + " " + string(hexNonce)

				base64Cipher := base64.StdEncoding.EncodeToString(hexCipher)
				base64Nonce := base64.StdEncoding.EncodeToString(hexNonce)

				response := field1 + " " + base64Cipher + " " + base64Nonce

				_, err_response := conn.WriteToUDP([]byte(response), clientAddr)
				if err_response != nil {
					log.Println("Error sending response to client:", err_response)
				}
				fmt.Println("Sent response %s", clientAddr.String())

			} else {

				fmt.Println("Data does not exist in the database:", data)
			}
		}(receivedData, addr)
	}
}

func issueNewKey(db *sql.DB, name string) (string, error) {

	random16, err := randomHexString(16)
	if err != nil {
		fmt.Printf("Failed to generate random: %v\n", err)
		return "", err
	}

	// Save to the database/ REPLACE / UPDATE
	_, err = db.Exec("UPDATE ubeken_keys SET data = ? WHERE name = ?", random16, name)
	if err != nil {
		log.Printf("Failed to insert into database: %v\n", err)
		return "", err
	}

	// Get last inserted ID
	//lastID, err := result.LastInsertId()
	//if err != nil {
	//	log.Printf("Failed to get last rowid: %v\n", err)
	//}
	//log.Printf("Isert randome16: %s rowid: %d \n", random16, lastID)

	return random16, nil

}

func existsAndDecrypts(db *sql.DB, dataStr string) (bool, string, string) {

	var exists bool
	var key string

	str := strings.Split(dataStr, " ")
	field1 := str[0] //name
	field2 := str[1] //cypher
	field3 := str[2] //nonce
	field4 := str[3] //seal

	err_query := db.QueryRow("SELECT EXISTS (SELECT 1 FROM ubeken_keys WHERE Name = ?), Data FROM ubeken_keys WHERE Name = ?", field1, field1).Scan(&exists, &key)
	if err_query != nil {
		log.Println("Error QueryRow database:", err_query)
		return false, "", ""
	}

	fmt.Println("Exists in db: " + field1)

	//key := []byte("0123456789ABCDEF0123456789ABCDEF") // 32 bytes for AES-256

	//decrypted, err := decrypt(base64Cipher, base64Nonce, base64Seal, []byte(key))
	decrypted, err := decrypt(field2, field3, field4, key)
	if err != nil {
		log.Println("Error decrypt:", err)
		return false, "", ""
	}
	//fmt.Println("Decrypted:  ", decrypted)

	return exists, key, decrypted
}

func createTables(db *sql.DB) error {

	// Create tables in the database

	sql1 := `CREATE TABLE IF NOT EXISTS ubeken_keys (
		"Name" TEXT PRIMARY KEY NOT NULL,
		"Data" TEXT,
		"Timestamp" DATETIME DEFAULT CURRENT_TIMESTAMP);`
	_, err := db.Exec(sql1)
	if err != nil {
		return err
	}

	sql2 := `CREATE TABLE IF NOT EXISTS ips (
        "Name" TEXT PRIMARY KEY NOT NULL,
        "Data" TEXT,
        "Timestamp" DATETIME DEFAULT CURRENT_TIMESTAMP);`
	_, err = db.Exec(sql2)
	if err != nil {
		return err
	}

	return nil
}

func getSqlite3Version(dbFile string) (string, error) {

	// Open the SQLite database from the given path
	db, err := sql.Open("sqlite3", dbFile)
	if err != nil {
		return "", fmt.Errorf("Error opening database: %v", err)
	}
	defer db.Close()

	version, err := sqlite3Version(db)
	if err != nil {
		return "", fmt.Errorf("Error getting SQLite version: %v", err)
	}

	return version, nil
}

func sqlite3Version(db *sql.DB) (string, error) {
	var version string
	err := db.QueryRow("SELECT SQLITE_VERSION()").Scan(&version)
	if err != nil {
		return "", err
	}
	return version, nil
}

func randomHexString(length int) (string, error) {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

/*






 */

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

func decrypt_V1(ciphertextHex string, nonceHex string, key []byte) (string, error) {

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

func decrypt(base64Cipher, base64Nonce, base64Seal string, keyStr string) (string, error) {
	// Trim whitespace and newlines from the key string
	keyStr = strings.TrimSpace(keyStr)

	// Debug output
	fmt.Println("Key:", keyStr)
	fmt.Println("Cipher:", base64Cipher)
	fmt.Println("Nonce:", base64Nonce)
	fmt.Println("Seal:", base64Seal)

	// Decode base64 strings to byte slices
	ciphertext, err := base64.StdEncoding.DecodeString(base64Cipher)
	if err != nil {
		return "", err
	}

	nonce, err := base64.StdEncoding.DecodeString(base64Nonce)
	if err != nil {
		return "", err
	}

	sealData, err := base64.StdEncoding.DecodeString(base64Seal)
	if err != nil {
		return "", err
	}

	// Create a new ChaCha20-Poly1305 AEAD cipher instance using the key
	cipher, err := chacha20poly1305.New([]byte(keyStr))
	if err != nil {
		return "", err
	}

	// Use the same nonce generation method as in Swift
	//generatedNonce := generateNonce()

	// Decrypt the ciphertext
	//decrypted, err := cipher.Open(nil, nonce, ciphertext, sealData)
	decrypted, err := cipher.Open(nil, nonce, ciphertext, sealData)
	if err != nil {
		return "", err
	}

	return string(decrypted), nil
}

func generateNonce() []byte {
	nonce := make([]byte, chacha20poly1305.NonceSize)
	_, err := io.ReadFull(rand.Reader, nonce)
	if err != nil {
		panic(err) // Handle this error more gracefully in your code
	}
	return nonce
}

/*

 */
