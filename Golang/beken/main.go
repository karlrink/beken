package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
    "strings"

    "time"
    "log"
    "sync"

    "os"

    "database/sql"

    _ "github.com/mattn/go-sqlite3"
)

type RequestBody struct {
	IP string `json:"ip"`
}

type CacheItem struct {
	timestamp time.Time
	exists    bool
}

type Cache struct {
	mu    sync.RWMutex
	tokens map[string]CacheItem
	ttl   time.Duration
}

func NewCache(ttl time.Duration) *Cache {
	return &Cache{
		tokens: make(map[string]CacheItem),
		ttl:    ttl,
	}
}

func (c *Cache) Exists(token string) (bool, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	item, ok := c.tokens[token]
	if ok && time.Since(item.timestamp) < c.ttl {
		return item.exists, true
	}
	return false, false
}

func (c *Cache) Set(token string, exists bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.tokens[token] = CacheItem{
		timestamp: time.Now(),
		exists:    exists,
	}
}

func tokenExistsInDBWithCache(db *sql.DB, cache *Cache, token string) bool {
	// Check in cache first
	exists, ok := cache.Exists(token)
	if ok {
		return exists
	}

	// If not in cache or expired, check in DB
	var inDB bool
	err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM tokens WHERE token=?)", token).Scan(&inDB)
	if err != nil {
		log.Printf("Error querying the database: %v\n", err)
		return false
	}

	// Cache the result
	cache.Set(token, inDB)

	return inDB
}


func setCorsHeaders(w http.ResponseWriter) {
	// You can change the value of the headers to fit your application needs
	w.Header().Set("Access-Control-Allow-Origin", "*") // You should switch "*" to specific origins in production.
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, beken-token")
}


func httpHandler(db *sql.DB, cache *Cache) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {

        clientIP := getClientIP(r)
        fmt.Printf("Received request from IP: %s\n", clientIP)

        setCorsHeaders(w) // Set CORS headers
        if r.Method == http.MethodOptions {
            // Pre-flight request. Reply successfully:
            w.WriteHeader(http.StatusOK)
            return
        }

        header_token := r.Header.Get("beken-token")
        if header_token == "" {
            //http.Error(w, "Header beken-token is missing", http.StatusBadRequest)
            http.Error(w, "No beken-token", http.StatusBadRequest)
            return
        }

        if !tokenExistsInDBWithCache(db, cache, header_token) {
            //fmt.Println("Not in sqlite3")
            http.Error(w, "Unknown beken-token", http.StatusBadRequest)
            return
        }


        if r.Method != http.MethodPost {
            //http.Error(w, "Only POST requests are allowed", http.StatusMethodNotAllowed)
            http.Error(w, "", http.StatusMethodNotAllowed)
            return
        }


        bodyBytes, err := ioutil.ReadAll(r.Body)
        if err != nil {
            http.Error(w, "Failed to read body", http.StatusInternalServerError)
            return
        }

        var requestBody RequestBody
        err = json.Unmarshal(bodyBytes, &requestBody)
        if err != nil {
            http.Error(w, "Failed to parse JSON", http.StatusBadRequest)
            return
        }

        response := fmt.Sprintf(`{"beken": "%s"}`, requestBody.IP)
        w.Header().Set("Content-Type", "application/json")
        w.Write([]byte(response))
    }
}

func getClientIP(r *http.Request) string {
	// Check for a proxy set client IP
	xForwardedFor := r.Header.Get("X-Forwarded-For")
	if xForwardedFor != "" {
		ips := strings.Split(xForwardedFor, ", ")
		if len(ips) > 0 {
			return ips[0]
		}
	}
	// If not set by proxy, then return the direct connection.
	return strings.Split(r.RemoteAddr, ":")[0] // This will remove the port number.
}


func createDb() error {

    if _, err := os.Stat("beken.db"); os.IsNotExist(err) {
        file, err := os.Create("beken.db")
        if err != nil {
            return err
        }
        file.Close()

        database, err := sql.Open("sqlite3", "beken.db")
        if err != nil {
            return err
        }
        defer database.Close()

        create := CreateTables(database)
        if create != nil {
            return create
        }

        fmt.Printf("Created beken.db \n")
    }
    return nil
}

func CreateTables(db *sql.DB) error {

    tokens_table := `CREATE TABLE tokens (
        "Token" TEXT PRIMARY KEY NOT NULL,
        "Data" TEXT,
        "Timestamp" DATETIME DEFAULT CURRENT_TIMESTAMP);`
    query1, err := db.Prepare(tokens_table)
    if err != nil {
        return err
    }
    _, err = query1.Exec()
    if err != nil {
        return err
    }

    return nil
}



func main() {

    err := createDb()
    if err != nil {
        panic(err)
    }

    database, err := sql.Open("sqlite3", "beken.db")
    if err != nil {
        log.Fatalf("Failed to open the database: %v", err) // Log and exit
    }
    defer database.Close()

    cache := NewCache(30 * time.Minute)
    http.HandleFunc("/beken", httpHandler(database, cache))
    port := "9480"
    fmt.Printf("Starting server on :%s\n", port)
    log.Fatal(http.ListenAndServe(":"+port, nil)) // Log any error from the server
}


