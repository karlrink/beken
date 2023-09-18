package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"database/sql"

	"github.com/fernet/fernet-go"
	_ "github.com/mattn/go-sqlite3"
)

var version = "1.0.0.🍁-2023-09-18"

func usage() {

	fmt.Println(`Usage: ` + os.Args[0] + ` </path/db> [port]

  --help|-help|help           Display this help message
  --version|-version|version  Display version

<db> 9480 # Default `)
}

func main() {

	//DEBUG=1 go run main.go
	PrintDebug("Debug mode enabled")

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

	// Create a buffer to hold incoming data
	buffer := make([]byte, 1024)

	// Open or create the SQLite3 database
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

			exists, decrypted := existsAndDecrypts(db, data)

			if exists {

				PrintDebug("decrypted: " + decrypted)

				// Convert clientAddr to a string
				clientAddrStr := clientAddr.String()

				// Remove the port from the IP address
				host, _, err := net.SplitHostPort(clientAddrStr) // works for IPv4 and IPv6 addresses
				if err != nil {
					log.Printf("Failed to split host and port: %v\n", err)
				}

				str := strings.Split(data, " ")
				field1 := str[0] //name
				field2 := str[1] //code
				//field3 := str[2] //cypher

				switch field2 {
				case "1": //rsa

					// Save the IP to the database
					_, err = db.Exec("INSERT INTO ips (Name, Data) VALUES (?, ?)", host, field1)
					if err != nil {
						log.Printf("Failed to save IP to database: %v\n", err)
					} else {
						log.Printf("Isert IP %s \n", host)
					}

					// Send a response back to the client
					response := "beken 1"

					_, err_response := conn.WriteToUDP([]byte(response), clientAddr)
					if err_response != nil {
						log.Println("Error sending response to client:", err_response)
					}
					log.Println("Sent response %s", clientAddr.String())

				case "2": //fernet

					// Save the IP to the database
					_, err = db.Exec("INSERT INTO ips (Name, Data) VALUES (?, ?)", host, field1)
					if err != nil {
						log.Printf("Failed to save IP to database: %v\n", err)
					} else {
						log.Printf("Isert IP %s \n", host)
					}
					// Send a response back to the client
					response := "beken 2"

					_, err_response := conn.WriteToUDP([]byte(response), clientAddr)
					if err_response != nil {
						log.Println("Error sending response to client:", err_response)
					}
					log.Println("Sent response %s", clientAddr.String())

				case "3": //aes

					// Save the IP to the database
					_, err = db.Exec("INSERT INTO ips (Name, Data) VALUES (?, ?)", host, field1)
					if err != nil {
						log.Printf("Failed to save IP to database: %v\n", err)
					} else {
						log.Printf("Isert IP %s \n", host)
					}
					// Send a response back to the client
					response := "beken 3"

					_, err_response := conn.WriteToUDP([]byte(response), clientAddr)
					if err_response != nil {
						log.Println("Error sending response to client:", err_response)
					}
					log.Println("Sent response %s", clientAddr.String())

				}

			} else {

				log.Println("Data does not exist in the database:", data)
			}
		}(receivedData, addr)
	}
}

func PrintDebug(message string) {
	debugMode := os.Getenv("DEBUG")
	if debugMode != "" {
		fmt.Println(message)
	}
}

func existsAndDecrypts(db *sql.DB, dataStr string) (bool, string) {

	var exists bool
	var key string

	str := strings.Split(dataStr, " ")
	field1 := str[0] //name
	field2 := str[1] //code
	field3 := str[2] //cypher

	switch field2 {
	case "1": //rsa
		err_query := db.QueryRow("SELECT EXISTS (SELECT 1 FROM private_keys WHERE Name = ?), Data FROM private_keys WHERE Name = ?", field1, field1).Scan(&exists, &key)
		if err_query != nil {
			log.Println("Error QueryRow database:", err_query)
			return false, ""
		}
		PrintDebug("Exists in db: " + field1)

		decrypted, err := decryptRSA(field3, key)
		if err != nil {
			log.Println("Error decrypt rsa:", err)
			return false, ""
		}
		//fmt.Println("Decrypted:  ", decrypted)

		return exists, decrypted

	case "2": //fernet
		err_query := db.QueryRow("SELECT EXISTS (SELECT 1 FROM fernet_keys WHERE Name = ?), Data FROM fernet_keys WHERE Name = ?", field1, field1).Scan(&exists, &key)
		if err_query != nil {
			log.Println("Error QueryRow database:", err_query)
			return false, ""
		}
		PrintDebug("Exists in db: " + field1)

		decrypted, err := decryptFernet(field3, key)
		if err != nil {
			log.Println("Error decrypt fernet:", err)
			return false, ""
		}
		//fmt.Println("Decrypted:  ", decrypted)

		return exists, decrypted

	case "3": //aes
		//field1 := str[0] //name
		//field2 := str[1] //code
		//field3 := str[2] //cypher
		field4 := str[3] //nonce
		field5 := str[4] //tag

		err_query := db.QueryRow("SELECT EXISTS (SELECT 1 FROM aes_keys WHERE Name = ?), Data FROM aes_keys WHERE Name = ?", field1, field1).Scan(&exists, &key)
		if err_query != nil {
			log.Println("Error QueryRow database:", err_query)
			return false, ""
		}
		PrintDebug("Exists in db: " + field1)

		decrypted, err := decryptAES(field3, field4, field5, key)
		if err != nil {
			log.Println("Error decrypt aes:", err)
			return false, ""
		}
		//fmt.Println("Decrypted:  ", decrypted)

		return exists, decrypted

	}
	return false, ""
}

func createTables(db *sql.DB) error {

	// Create tables in the database

	sql1 := `CREATE TABLE IF NOT EXISTS private_keys (
		"Name" TEXT PRIMARY KEY NOT NULL,
		"Data" TEXT,
		"Timestamp" DATETIME DEFAULT CURRENT_TIMESTAMP);`
	_, err := db.Exec(sql1)
	if err != nil {
		return err
	}

	sql2 := `CREATE TABLE IF NOT EXISTS fernet_keys (
        "Name" TEXT PRIMARY KEY NOT NULL,
        "Data" TEXT,
        "Timestamp" DATETIME DEFAULT CURRENT_TIMESTAMP);`
	_, err = db.Exec(sql2)
	if err != nil {
		return err
	}

	sql3 := `CREATE TABLE IF NOT EXISTS aes_keys (
        "Name" TEXT PRIMARY KEY NOT NULL,
        "Data" TEXT,
        "Timestamp" DATETIME DEFAULT CURRENT_TIMESTAMP);`
	_, err = db.Exec(sql3)
	if err != nil {
		return err
	}

	sql4 := `CREATE TABLE IF NOT EXISTS ips (
        "Name" TEXT PRIMARY KEY NOT NULL,
        "Data" TEXT,
        "Timestamp" DATETIME DEFAULT CURRENT_TIMESTAMP);`
	_, err = db.Exec(sql4)
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

/*






 */

func decryptRSA(base64Cipher, keyStr string) (string, error) {

	// Decode base64 strings to byte
	ciphertext, err := base64.StdEncoding.DecodeString(base64Cipher)
	if err != nil {
		return "", err
	}

	privateKeyPEM := []byte(keyStr)

	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		fmt.Println("Error decoding private key")
		return "", err
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		fmt.Println("Error parsing private key:", err)
		return "", err
	}

	// Decrypt the data using the private key
	decryptedData, err := rsa.DecryptPKCS1v15(nil, privateKey, ciphertext)
	if err != nil {
		//fmt.Println("Error decrypting rsa:", err)
		return "", err
	}

	return string(decryptedData), nil
}

func decryptFernet(base64Cipher, keyStr string) (string, error) {

	//keyStr := "12345678901234567890123456789012"

	// Encode the key as a base64 string
	base64Key := base64.StdEncoding.EncodeToString([]byte(keyStr))
	//fmt.Println("base64 key: " + base64Key)
	//k := fernet.MustDecodeKeys("cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=")
	k := fernet.MustDecodeKeys(base64Key)

	//base64tok := os.Args[1]

	// Decode the base64 string
	decodedBytes, err := base64.StdEncoding.DecodeString(base64Cipher)
	if err != nil {
		fmt.Println("Error decoding base64:", err)
		return "", err
	}

	//tokStr := string(tok)
	//fmt.Println("Encrypted: " + tok)

	msg := fernet.VerifyAndDecrypt([]byte(decodedBytes), 60*time.Second, k)

	//fmt.Println(string(msg))

	return string(msg), nil
}

func decryptAES(base64Cipher, base64Nonce, base64Tag, keyStr string) (string, error) {

	// Decode the Base64 strings to []byte
	cipherText, err := base64.StdEncoding.DecodeString(base64Cipher)
	if err != nil {
		log.Println("Error decoding ciphertext:", err)
		return "", err
	}

	nonce, err := base64.StdEncoding.DecodeString(base64Nonce)
	if err != nil {
		log.Println("Error decoding nonce:", err)
		return "", err
	}

	tag, err := base64.StdEncoding.DecodeString(base64Tag)
	if err != nil {
		log.Println("Error decoding tag:", err)
		return "", err
	}

	// Your AES encryption key (must be the same as the one used for encryption)
	//key := []byte("YOUR_AES_KEY_HERE")

	key := []byte(keyStr)
	log.Println("keyStr: " + keyStr)

	// Create a new AES block cipher with your key
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Println("Error creating AES cipher:", err)
		return "", err
	}

	// Create a GCM cipher with the block cipher and the nonce
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		log.Println("Error creating GCM cipher:", err)
		return "", err
	}

	// Decrypt the ciphertext
	plainText, err := aesGCM.Open(nil, nonce, cipherText, tag)
	if err != nil {
		//log.Println("Error decrypting aes:", err)
		return "", err
	}

	// Convert the plaintext to a string and print it
	log.Println("Decrypted Text:", string(plainText))

	return string(plainText), nil
}

/*

 */
