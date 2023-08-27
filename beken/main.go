package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	//"net"
	"path/filepath"

	"log"
	"sync"
	"time"

	"os"
	//"os/exec"

	"database/sql"

	_ "github.com/mattn/go-sqlite3"
)

var version = "1.0.0.🐕-2023-08-27"

type RequestBody struct {
	IP string `json:"ip"`
}

type CacheItem struct {
	timestamp time.Time
	exists    bool
}

type Cache struct {
	mu     sync.RWMutex
	tokens map[string]CacheItem
	ttl    time.Duration
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
	err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM tokens WHERE name=?)", token).Scan(&inDB)
	if err != nil {
		log.Printf("Error querying the database: %v\n", err)
		return false
	}

	// Cache the result
	cache.Set(token, inDB)

	return inDB
}

var expireDuration = 31536000 // This is for 1 year in seconds

func tokenExistsInDBWithCacheTime(db *sql.DB, cache *Cache, token string, expireDuration int) bool {
	// Check in cache first
	exists, ok := cache.Exists(token)
	if ok {
		return exists
	}

	// If not in cache or expired, check in DB
	var inDB bool
	var timestamp time.Time
	query := "SELECT EXISTS(SELECT 1 FROM tokens WHERE name=?), Timestamp FROM tokens WHERE name=?"
	err := db.QueryRow(query, token, token).Scan(&inDB, &timestamp)
	if err != nil {
		log.Printf("Error querying the database: %v\n", err)
		return false
	}

	// Check if token is expired based on the timestamp
	if time.Since(timestamp).Seconds() > float64(expireDuration) {
		log.Printf("Expired Token.\n")
		inDB = false // if the token is expired, set it as not in DB
	}

	// Cache the result with an expiration duration
	//cache.Set(token, inDB, time.Duration(expireDuration)*time.Second)

	// Cache the result
	cache.Set(token, inDB)

	return inDB
}

func ipExistsInDB(db *sql.DB, ip string) bool {
	var exists bool
	err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM ips WHERE name=?)", ip).Scan(&exists)
	if err != nil {
		log.Printf("Error querying the database for IP: %v\n", err)
		return false
	}
	return exists
}

func setCorsHeaders(w http.ResponseWriter) {
	// You can change the value of the headers to fit your application needs
	w.Header().Set("Access-Control-Allow-Origin", "*") // You should switch "*" to specific origins in production.
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, beken-token")
}

func httpPostHandler(db *sql.DB, cache *Cache) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		clientIP := getClientIP(r)
		log.Printf("Received POST /post request from IP: %s\n", clientIP)

		setCorsHeaders(w) // Set CORS headers
		if r.Method == http.MethodOptions {
			// Pre-flight request. Reply successfully:
			w.WriteHeader(http.StatusOK)
			return
		}

		if r.Method != http.MethodPost {
			//http.Error(w, "Only POST requests are allowed", http.StatusMethodNotAllowed)
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}

		header_token := r.Header.Get("beken-token")
		if header_token == "" {
			//http.Error(w, "Header beken-token is missing", http.StatusBadRequest)
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}

		if !tokenExistsInDBWithCacheTime(db, cache, header_token, expireDuration) {
			http.Error(w, "Unauthorized Request", http.StatusUnauthorized)
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

		//success

		// Save the IP to the database
		_, err = db.Exec("INSERT INTO ips (Name, Data) VALUES (?, ?)", requestBody.IP, header_token)
		if err != nil {
			if strings.Contains(err.Error(), "UNIQUE constraint failed: ips.Name") {
				//response := fmt.Sprintf("IP address %s is already in the database", requestBody.IP)
				response := fmt.Sprintf(`{"beken": "%s", "exists": true}`, requestBody.IP)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK) // Send a 200 OK status
				w.Write([]byte(response))
				log.Printf("Isert IP attempt by %s \n", clientIP)
				return
			}

			log.Printf("Failed to save IP to database: %v\n", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		log.Printf("Isert IP %s \n", requestBody.IP)

		response := fmt.Sprintf(`{"beken": "%s"}`, requestBody.IP)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK) // Send a 200 OK status
		w.Write([]byte(response))
	}
}

func httpIPHandler(db *sql.DB, cache *Cache) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		clientIP := getClientIP(r)
		log.Printf("Received GET /ip request from IP: %s\n", clientIP)

		setCorsHeaders(w) // Set CORS headers
		if r.Method == http.MethodOptions {
			// Pre-flight request. Reply successfully:
			w.WriteHeader(http.StatusOK)
			return
		}

		if r.Method != http.MethodGet {
			//http.Error(w, "Only GET requests are allowed", http.StatusMethodNotAllowed)
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}

		header_token := r.Header.Get("beken-token")
		if header_token == "" {
			//http.Error(w, "Header beken-token is missing", http.StatusBadRequest)
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}

		if !tokenExistsInDBWithCacheTime(db, cache, header_token, expireDuration) {
			http.Error(w, "Unauthorized Request", http.StatusUnauthorized)
			return
		}

		/*
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
		*/

		if !ipExistsInDB(db, clientIP) {
			response := fmt.Sprintf(`{"ip": "%s", "exists": false}`, clientIP)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK) // Send a 200 OK status
			w.Write([]byte(response))
			return
		}

		response := fmt.Sprintf(`{"ip": "%s", "exists": true}`, clientIP)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK) // Send a 200 OK status
		w.Write([]byte(response))

	}
}

func httpTokenHandler(db *sql.DB, cache *Cache) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		clientIP := getClientIP(r)
		log.Printf("Received GET /token request from IP: %s\n", clientIP)

		setCorsHeaders(w) // Set CORS headers
		if r.Method == http.MethodOptions {
			// Pre-flight request. Reply successfully:
			w.WriteHeader(http.StatusOK)
			return
		}

		if r.Method != http.MethodGet {
			//http.Error(w, "Only GET requests are allowed", http.StatusMethodNotAllowed)
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}

		header_token := r.Header.Get("beken-token")
		if header_token == "" {
			//http.Error(w, "Header beken-token is missing", http.StatusBadRequest)
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}

		if !tokenExistsInDBWithCacheTime(db, cache, header_token, expireDuration) {
			http.Error(w, "Unauthorized Request", http.StatusUnauthorized)
			return
		}

		/*
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
		*/

		if !ipExistsInDB(db, clientIP) {
			response := fmt.Sprintf(`{"ip": "%s", "exists": false}`, clientIP)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK) // Send a 200 OK status
			w.Write([]byte(response))
			return
		}

		response := fmt.Sprintf(`{"ip": "%s", "exists": true}`, clientIP)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK) // Send a 200 OK status
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

func createDb(bekenDb string) error {

	if _, err := os.Stat(bekenDb); os.IsNotExist(err) {
		file, err := os.Create(bekenDb)
		if err != nil {
			return err
		}
		file.Close()

		database, err := sql.Open("sqlite3", bekenDb)
		if err != nil {
			return err
		}
		defer database.Close()

		create := CreateTables(database)
		if create != nil {
			return create
		}

		log.Printf("Created %s \n", bekenDb)
	}
	return nil
}

func CreateTables(db *sql.DB) error {

	tokens_table := `CREATE TABLE tokens (
        "Name" TEXT PRIMARY KEY NOT NULL,
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

	ips_table := `CREATE TABLE ips (
        "Name" TEXT PRIMARY KEY NOT NULL,
        "Data" TEXT,
        "Timestamp" DATETIME DEFAULT CURRENT_TIMESTAMP);`
	query2, err := db.Prepare(ips_table)
	if err != nil {
		return err
	}
	_, err = query2.Exec()
	if err != nil {
		return err
	}

	configs_table := `CREATE TABLE configs (
        "Name" TEXT PRIMARY KEY NOT NULL,
        "Data" JSON,
        "Timestamp" DATETIME DEFAULT CURRENT_TIMESTAMP);`
	query3, err := db.Prepare(configs_table)
	if err != nil {
		return err
	}
	_, err = query3.Exec()
	if err != nil {
		return err
	}

	procs_table := `CREATE TABLE procs (
        "Name" TEXT,
        "Data" TEXT,
        "Timestamp" DATETIME DEFAULT CURRENT_TIMESTAMP);`
	query4, err := db.Prepare(procs_table)
	if err != nil {
		return err
	}
	_, err = query4.Exec()
	if err != nil {
		return err
	}

	return nil
}

func contentTypeSetter(next http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Check file extensions and set MIME types accordingly
		if strings.HasSuffix(r.URL.Path, ".css") {
			w.Header().Set("Content-Type", "text/css")
		} else if strings.HasSuffix(r.URL.Path, ".js") {
			w.Header().Set("Content-Type", "application/javascript")
		}
		// Call the next handler (in this case, the FileServer)
		next.ServeHTTP(w, r)
	}
}

func main() {

	basePath := ""
	if len(os.Args) > 1 {
		basePath = os.Args[1]
	}

	bekenLog := filepath.Join(basePath, "beken.log")
	bekenDb := filepath.Join(basePath, "beken.db")

	// Setup logger to write to beken.log
	logFile, err := os.OpenFile(bekenLog, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		panic(err)
	}
	defer logFile.Close()

	logger := log.New(logFile, "", log.LstdFlags)
	log.SetOutput(logFile) // Redirect standard logger to the file

	err = createDb(bekenDb)
	if err != nil {
		logger.Fatalf("Failed to create the database: %v", err) // Log and exit
	}

	database, err := sql.Open("sqlite3", bekenDb)
	if err != nil {
		logger.Fatalf("Failed to open the database: %v", err) // Log and exit
	}
	defer database.Close()

	cache := NewCache(30 * time.Minute)
	http.HandleFunc("/beken/post", httpPostHandler(database, cache))
	http.HandleFunc("/beken/ip", httpIPHandler(database, cache))
	http.HandleFunc("/beken/token", httpTokenHandler(database, cache))

	// Serve static content
	http.Handle("/beken/client/", contentTypeSetter(http.StripPrefix("/beken/client", http.FileServer(http.Dir("./static_content")))))

	port := "9480"
	logger.Printf("Starting server %s on port:%s\n", version, port)
	logger.Fatal(http.ListenAndServe(":"+port, nil)) // Log any error from the server
}
