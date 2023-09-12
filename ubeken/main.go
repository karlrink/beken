package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"database/sql"

	_ "github.com/mattn/go-sqlite3"
)

var version = "1.0.0.🍁-2023-09-12"

type CacheEntry struct {
	Exists     bool
	Expiration time.Time
}

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

		//default:
		//	dbFile := os.Args[1]
	}

	dbFile := os.Args[1]
	//sqlite3File := os.Args[1]

	var defaultPort = "9480"

	if len(os.Args) > 2 {
		// Check if os.Args[2] is provided
		defaultPort = os.Args[2]
	}
	// Define the address to listen on
	//address := ":9480"
	address := ":" + defaultPort

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

	// Create a table in the database
	//_, err = db.Exec("CREATE TABLE IF NOT EXISTS udp_data (data TEXT)")
	//if err != nil {
	//	log.Fatal("Error creating table:", err)
	//}

	create := createTables(db)
	if create != nil {
		log.Fatal("Error creating tables:", create)
	}

	log.Println("UDP server listening on " + address)

	// Define a cache expiration duration (e.g., 5 minutes)
	expirationDuration := 5 * time.Minute

	// Start a Goroutine to periodically clean up expired entries from the cache
	go cleanupCache(expirationDuration)

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

			// Convert clientAddr to a string
			//clientAddrStr := clientAddr.String()

			//receivedData := "x xxxxxxx"
			//str := strings.Split(data, " ")
			//field1 := str[0]
			//field2 := str[1]

			/*
				// Check the cache first
				exists, cached := getFromCache(data, expirationDuration)
				if !cached {
					exists = existsData(db, data)
					addToCache(data, exists, expirationDuration)
				}
			*/

			exists := existsDecrypts(db, data)

			if exists {

				fmt.Println("Data exists and decrypts:", data)

				// add clientAddr to db

				// Save the IP to the database
				_, err = db.Exec("INSERT INTO ips (Name, Data) VALUES (?, ?)", clientAddr.String(), "")
				if err != nil {
					log.Printf("Failed to save IP to database: %v\n", err)
				} else {
					log.Printf("Isert IP %s \n", clientAddr.String())
				}

				// Send a response back to the client
				response := "your udp received"
				_, err := conn.WriteToUDP([]byte(response), clientAddr)
				if err != nil {
					log.Println("Error sending response to client:", err)
				}
				fmt.Println("Sent response %s", clientAddr.String())

			} else {

				fmt.Println("Data does not exist in the database:", data)
			}
		}(receivedData, addr)
	}
}

var cacheMutex sync.RWMutex
var cache = make(map[string]CacheEntry)

func existsDecrypts(db *sql.DB, dataStr string) bool {

	var exists bool
	var data string

	str := strings.Split(dataStr, " ")
	field1 := str[0] //name
	field2 := str[1] //cypher
	field3 := str[2] //nonce

	err := db.QueryRow("SELECT EXISTS (SELECT 1 FROM client_keys WHERE Name = ?), Data FROM client_keys WHERE Name = ?", field1, field1).Scan(&exists, &data)
	if err != nil {
		log.Println("Error QueryRow database:", err)
		return false
	}

	//fmt.Println(data) //key
	//fmt.Println("base64: " + field2)
	//fmt.Println("base64: " + field3)

	//key := []byte("0123456789ABCDEF0123456789ABCDEF") // 32 bytes for AES-256
	key := []byte(data) // 32 bytes for AES-256

	decrypted, err := decrypt(field2, field3, key)
	if err != nil {
		log.Println("Error decrypt:", err)
		return false
	}
	fmt.Println("Decrypted:  ", decrypted)

	return exists
}

func decrypt(base64Ciphertext string, base64Nonce string, key []byte) (string, error) {

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	decodedCiphertext, err := base64.StdEncoding.DecodeString(base64Ciphertext)
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

func getFromCache(data string, expiration time.Duration) (bool, bool) {
	cacheMutex.RLock()
	entry, cached := cache[data]
	cacheMutex.RUnlock()

	if cached && time.Now().Before(entry.Expiration) {
		return entry.Exists, true
	}

	return false, false
}

func addToCache(data string, exists bool, expiration time.Duration) {
	cacheMutex.Lock()
	cache[data] = CacheEntry{
		Exists:     exists,
		Expiration: time.Now().Add(expiration),
	}
	cacheMutex.Unlock()
}

func cleanupCache(expiration time.Duration) {
	for {
		time.Sleep(expiration)

		cacheMutex.Lock()
		for data, entry := range cache {
			if time.Now().After(entry.Expiration) {
				delete(cache, data)
			}
		}
		cacheMutex.Unlock()
	}
}

func createTables(db *sql.DB) error {

	// Create tables in the database

	sql1 := `CREATE TABLE IF NOT EXISTS client_keys (
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

/*






 */
