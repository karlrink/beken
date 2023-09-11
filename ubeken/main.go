package main

import (
	"database/sql"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

type CacheEntry struct {
	Exists     bool
	Expiration time.Time
}

func main() {
	// Define the address to listen on
	address := ":9480"

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

	fmt.Println("UDP server listening on all network interfaces at port 9480")

	// Create a buffer to hold incoming data
	buffer := make([]byte, 1024)

	// Open or create the SQLite3 database
	db, err := sql.Open("sqlite3", "udp_database.db")
	if err != nil {
		log.Fatal("Error opening database:", err)
	}
	defer db.Close()

	// Create a table in the database
	_, err = db.Exec("CREATE TABLE IF NOT EXISTS udp_data (data TEXT)")
	if err != nil {
		log.Fatal("Error creating table:", err)
	}

	// Define a cache expiration duration (e.g., 5 minutes)
	expirationDuration := 5 * time.Minute

	// Start a Goroutine to periodically clean up expired entries from the cache
	go cleanupCache(expirationDuration)

	for {
		// Read data from the connection
		n, _, err := conn.ReadFromUDP(buffer)
		if err != nil {
			log.Println("Error reading from UDP connection:", err)
			continue
		}

		receivedData := string(buffer[:n])

		// Process each packet in a Goroutine
		go func(data string) {
			// Check the cache first

			exists, cached := getFromCache(data, expirationDuration)

			if !cached {
				exists = existsData(db, data)
				addToCache(data, exists, expirationDuration)
			}

			if exists {
				fmt.Println("Data exists in the database:", data)
			} else {
				fmt.Println("Data does not exist in the database:", data)
			}
		}(receivedData)
	}
}

var cacheMutex sync.RWMutex
var cache = make(map[string]CacheEntry)

func existsData(db *sql.DB, data string) bool {
	var exists bool
	err := db.QueryRow("SELECT EXISTS (SELECT 1 FROM udp_data WHERE data = ?)", data).Scan(&exists)
	if err != nil {
		log.Println("Error checking database:", err)
		return false
	}
	return exists
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
