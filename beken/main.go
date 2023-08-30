package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
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

var version = "1.0.0.🐕-2023-08-29"

type RequestBody struct {
	IP   string `json:"ip"`
	User string `json:"user"`
	Pass string `json:"pass"`
	Iv   string `json:"iv"`
	Id   int    `json:"id"`
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
		log.Printf("Received POST /beken/post request from IP: %s\n", clientIP)

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
		log.Printf("Received GET /beken/ip request from IP: %s\n", clientIP)

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
		log.Printf("Received POST /beken/token request from IP: %s\n", clientIP)

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

		//success

		random16, err := randomString(16)
		if err != nil {
			fmt.Printf("Failed to generate random: %v\n", err)
			http.Error(w, "Internal server error - Failed to generate random", http.StatusInternalServerError)
			return
		}

		// Save to the database
		result, err := db.Exec("INSERT INTO keys (Name, Data) VALUES (?, ?)", random16, header_token)
		if err != nil {
			log.Printf("Failed to insert into database: %v\n", err)
			http.Error(w, "Internal server error - Failed insert into database", http.StatusInternalServerError)
			return
		}

		// Get last inserted ID
		lastID, err := result.LastInsertId()
		if err != nil {
			log.Printf("Failed to get last rowid: %v\n", err)
		}

		log.Printf("Isert randome16: %s rowid: %d \n", random16, lastID)

		response := fmt.Sprintf(`{"key": "%s", "id": %d}`, random16, lastID)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK) // Send a 200 OK status
		w.Write([]byte(response))

	}
}

func httpPassHandler(db *sql.DB, cache *Cache) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		clientIP := getClientIP(r)
		log.Printf("Received POST /beken/pass request from IP: %s\n", clientIP)

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
			http.Error(w, "Header beken-token is missing", http.StatusBadRequest)
			//http.Error(w, "Bad Request", http.StatusBadRequest)
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

		//requestBody.Pass
		//requestBody.User
		//requestBody.Id

		//success

		nameData := requestBody.Pass + " " + requestBody.Iv
		dataData := requestBody.User

		// Insert into the database
		_, err_query := db.Exec("INSERT INTO crypts (Name, Data) VALUES (?, ?)", nameData, dataData)
		if err_query != nil {
			log.Printf("Failed to insert into database: %v\n", err_query)
			http.Error(w, "Internal server error - Failed insert into database", http.StatusInternalServerError)
			return
		}
		log.Printf("Isert crypts Name %s User %s \n", requestBody.Pass, requestBody.User)

		// get last insert id here
		// Get last inserted ID
		//lastID, err := result.LastInsertId()
		//if err != nil {
		//	log.Printf("Failed to get last rowid: %v\n", err)
		//}

		//prepar new token, put in db, and send back to client

		// TODO

		// need pass.  is decrypt
		//<db>  de-crypt name iv key
		// decryptName(name, iv, key)
		//
		// name, iv are requestBody.Pass split.(' ')
		// key is in db... lastID?

		//lookup key in db (header_token is data list-keys)
		var keyStr string

		//var keyId int

		//FIX WRONG QUERY gets wrong key...
		//./touer ../beken/beken.db de-crypt VgjHjrIZNLUJLa3ic0Mo4faf DX853dDYDmhZIa6Q a6369dcf5fa35aa471983e4448b27ce7
		//./touer ../beken/beken.db de-crypt VgjHjrIZNLUJLa3ic0Mo4faf DX853dDYDmhZIa6Q 12c1f4af944c8981050e3b4bcb7bc2c9

		//err := db.QueryRow("SELECT name from keys where data = ?", header_token)

		//query1 := db.QueryRow("SELECT name from keys where data = ?", header_token).Scan(&keyStr)

		// Convert string to integer using strconv.Atoi
		//keyId, err := strconv.Atoi(requestBody.Id)
		//if err != nil {
		//	log.Printf("Failed Conversion error: %v\n", err)
		//	http.Error(w, "Internal server error - Failed Conversion", http.StatusInternalServerError)
		//	return
		//}
		//query1 := db.QueryRow("SELECT name from keys where rowid = ?", keyId).Scan(&keyStr)

		log.Printf("requestBody.User: %s\n", requestBody.User)
		log.Printf("requestBody.Pass: %s\n", requestBody.Pass)
		log.Printf("requestBody.Iv: %s\n", requestBody.Iv)
		log.Printf("requestBody.Id: %d\n", requestBody.Id)

		query1 := db.QueryRow("SELECT name from keys where rowid = ?", requestBody.Id).Scan(&keyStr)

		//keyId
		//query1 := db.QueryRow("SELECT name from keys where rowid = ?", keyId).Scan(&keyStr)

		if query1 != nil {
			log.Printf("Failed SELECT name from keys: %v\n", query1)
			http.Error(w, "Internal server error - Failed SELECT database", http.StatusInternalServerError)
			return
		}

		//now decrypt name iv keyStr

		//log.Printf(key_data)
		//splitted := strings.Fields(key_data)
		//splitted := strings.Fields(requestBody.Pass)
		//cTxt := splitted[0]
		//cIv := splitted[1]

		//err := decryptName(unBase64Ciphertext, base64Iv, keyStr)
		//decrypted, err := decryptName(cTxt, cIv, keyStr)
		//decrypted, err := decryptName(cTxt, cIv, keyStr)

		//log.Printf(cTxt)
		//log.Printf(cIv)
		//log.Printf(keyStr)

		//decrypted, err := decryptName(cTxt, cIv, keyStr)
		decrypted, err := decryptName(requestBody.Pass, requestBody.Iv, keyStr)
		if err != nil {
			log.Printf("Failed decrypt: %v\n", err)
			http.Error(w, "Internal server error - Failed decrypt", http.StatusInternalServerError)
			return
		}

		// user : pass concat
		// Concatenate the username and password with a colon
		//data := requestBody.User + ":" + pass
		data := requestBody.User + ":" + decrypted

		// Compute SHA-256 hash
		hash := sha256.New()
		hash.Write([]byte(data))
		hashedData := hash.Sum(nil)

		//log.Printf("hash data: %v\n", hashedData)

		// Perform Base64 encoding
		base64Encoded := base64.StdEncoding.EncodeToString(hashedData)

		//log.Printf("base64Encoded: %v\n", base64Encoded)

		newToken := "bt-" + base64Encoded

		//response := fmt.Sprintf(`{"ip": "%s", "pass": true}`, clientIP)
		response := fmt.Sprintf(`{"beken-token": "%s"}`, newToken)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK) // Send a 200 OK status
		w.Write([]byte(response))

		log.Printf("Sent: %s\n", response)

	}
}

func decryptName(base64Ciphertext string, base64Iv string, key string) (string, error) {

	unBase64Ciphertext, err := base64.StdEncoding.DecodeString(base64Ciphertext)
	if err != nil {
		return "", err
	}

	unBase64Iv, err := base64.StdEncoding.DecodeString(base64Iv)
	if err != nil {
		return "", err
	}

	decrypted, err := aesDecrypt(unBase64Ciphertext, []byte(key), unBase64Iv)
	if err != nil {
		return "", err
	}

	//fmt.Println(string(decrypted)) // Convert byte array to string here
	//return nil
	return string(decrypted), nil
}

func aesDecrypt(ciphertext []byte, key []byte, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plainTextBytes, err := gcm.Open(nil, iv, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plainTextBytes, nil
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

	crypts_table := `CREATE TABLE crypts (
        "Name" TEXT PRIMARY KEY NOT NULL,
        "Data" TEXT,
        "Timestamp" DATETIME DEFAULT CURRENT_TIMESTAMP);`
	query5, err := db.Prepare(crypts_table)
	if err != nil {
		return err
	}
	_, err = query5.Exec()
	if err != nil {
		return err
	}

	keys_table := `CREATE TABLE keys (
        "Name" TEXT PRIMARY KEY NOT NULL,
        "Data" TEXT,
        "Timestamp" DATETIME DEFAULT CURRENT_TIMESTAMP);`
	query6, err := db.Prepare(keys_table)
	if err != nil {
		return err
	}
	_, err = query6.Exec()
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

func randomString(length int) (string, error) {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
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
	http.HandleFunc("/beken/pass", httpPassHandler(database, cache))

	// Serve static content
	http.Handle("/beken/client/", contentTypeSetter(http.StripPrefix("/beken/client", http.FileServer(http.Dir("./static_content/client")))))
	http.Handle("/beken/password/", contentTypeSetter(http.StripPrefix("/beken/password", http.FileServer(http.Dir("./static_content/password")))))

	/*
		http.HandleFunc("/beken/client/", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/beken/client", http.StatusMovedPermanently)
		})

		http.HandleFunc("/beken/password/", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/beken/password", http.StatusMovedPermanently)
		})
	*/

	port := "9480"
	logger.Printf("Starting server %s on port:%s\n", version, port)
	logger.Fatal(http.ListenAndServe(":"+port, nil)) // Log any error from the server
}
