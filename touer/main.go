package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"database/sql"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/term"
)

var version = "1.0.0.🐕-2023-08-29"

func usage() string {

	usage := `Usage: ` + os.Args[0] + ` </path/db> [option]

  --help|-help|help           Display this help message
  --version|-version|version  Display version

Options:

<db>  list-tables

<db>  proc-ips

<db>  list-procs
<db>  del-proc n
<db>  purge-procs

<db>  list-ips
<db>  add-ip ip data
<db>  del-ip ip
<db>  purge-ips

<db>  list-tokens
<db>  add-token token data
<db>  set-token-time token 2021-01-01T16:20:00Z
<db>  del-token token
<db>  purge-tokens

<db>  gen-token

<db>  list-configs
<db>  add-config name json
<db>  del-config name
<db>  purge-configs

<db>  list-crypts
<db>  add-crypt n name data
<db>  del-crypt name
<db>  de-crypt name iv key
<db>  purge-crypts

<db>  list-keys
<db>  add-key n name data
<db>  del-key name
<db>  purge-keys

`
	return usage
}

func main() {

	if len(os.Args) < 2 {
		Errorf(usage())
	}

	switch os.Args[1] {
	case "--help", "-help", "help":
		Errorf(usage())
	case "--version", "-version", "version":
		Println("Version: " + version)
		sqlite3version, err := getSqlite3Version(os.Args[1])
		if err != nil {
			Errorf("Failed to get SQLite version: %v\n", err)
		}
		Println("Sqlite3: " + sqlite3version)
		return
	}

	dbFile := os.Args[1]

	// Check if the file exists
	if _, err := os.Stat(dbFile); os.IsNotExist(err) {
		Errorf("File not found: %s\n", dbFile)
	}
	// Connect to the SQLite3 database file
	db, err := sql.Open("sqlite3", dbFile)
	if err != nil {
		Errorf("Failed to connect: %s\n", err)
	}
	defer db.Close()

	// Check if the database connection is valid by pinging it
	if err := db.Ping(); err != nil {
		Errorf("Failed to ping the database: %v\n", err)
	}

	if len(os.Args) > 2 {

		switch os.Args[2] {

		case "list-tables":
			listTables(db)
		case "list-ips":
			//listIps(db)
			listDataRows(db, "ips")
		case "list-tokens":
			//listTokens(db)
			listDataRows(db, "tokens")
		case "list-procs":
			listProcs(db)
			//listDataRows(db, "procs")

		case "proc-ips":
			//listNewIPDb(db)
			procIps(db)

		case "list-crypts":
			listDataRows(db, "crypts")

		case "add-crypt":
			rowid := os.Args[3]
			name := os.Args[4]
			data := os.Args[5]

			rowidInt, err := strconv.Atoi(rowid)
			if err != nil {
				fmt.Printf("Could not convert rowid to integer: %v\n", err)
				return
			}

			err_insert := insertIdData(db, "crypts", rowidInt, name, data)
			if err_insert != nil {
				Errorf("Failed to insert: %v\n", err_insert)
			}

		case "del-crypt":
			crypt := os.Args[3]
			err := delName(db, "crypts", crypt)
			if err != nil {
				Errorf("Failed to del: %v\n", err)
			}

		case "de-crypt":
			name := os.Args[3]
			iv := os.Args[4]
			key := os.Args[5]
			decryptName(name, iv, key)

		case "purge-crypts":
			err := truncateTable(db, "crypts")
			if err != nil {
				Errorf("Failed to purge: %v\n", err)
			}

		case "list-keys":
			listDataRows(db, "keys")

		case "add-key":
			rowid := os.Args[3]
			name := os.Args[4]
			data := os.Args[5]

			rowidInt, err := strconv.Atoi(rowid)
			if err != nil {
				fmt.Printf("Could not convert rowid to integer: %v\n", err)
				return
			}

			err_insert := insertIdData(db, "keys", rowidInt, name, data)
			if err_insert != nil {
				Errorf("Failed to insert: %v\n", err_insert)
			}

		case "purge-keys":
			err := truncateTable(db, "keys")
			if err != nil {
				Errorf("Failed to purge: %v\n", err)
			}

		case "add-ip":
			ip := os.Args[3]
			data := os.Args[4]
			err := insertNameData(db, "ips", ip, data)
			if err != nil {
				Errorf("Failed to insert: %v\n", err)
			}
		case "add-token":
			token := os.Args[3]
			data := os.Args[4]
			err := insertNameData(db, "tokens", token, data)
			if err != nil {
				Errorf("Failed to insert: %v\n", err)
			}

		case "set-token-time":
			token := os.Args[3]
			time := os.Args[4]
			err := updateNameTime(db, "tokens", token, time)
			if err != nil {
				Errorf("Failed to insert: %v\n", err)
			}

		case "del-ip":
			ip := os.Args[3]
			err := delName(db, "ips", ip)
			if err != nil {
				Errorf("Failed to del: %v\n", err)
			}

		case "del-token":
			token := os.Args[3]
			err := delName(db, "tokens", token)
			if err != nil {
				Errorf("Failed to del: %v\n", err)
			}

		case "del-proc":
			proc := os.Args[3]
			n, err := strconv.Atoi(proc)
			if err != nil {
				Errorf("Error converting rowid to integer: %v\n", err)
			}

			del := deleteId(db, "procs", n)
			if del != nil {
				Errorf("Failed to del: %v\n", del)
			}

		case "purge-procs":
			err := truncateTable(db, "procs")
			if err != nil {
				Errorf("Failed to purge: %v\n", err)
			}

		case "purge-ips":
			err := truncateTable(db, "ips")
			if err != nil {
				Errorf("Failed to purge: %v\n", err)
			}

		case "purge-tokens":
			err := truncateTable(db, "tokens")
			if err != nil {
				Errorf("Failed to purge: %v\n", err)
			}

		case "gen-token":
			err := genToken(db)
			if err != nil {
				Errorf("Failed: %v\n", err)
			}

		default:
			Println("Invalid argument: " + os.Args[2])
		}
		return
	}

	Println(`{"sqlite3":true}`)
}

func Errorf(format string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, format, a...)
	os.Exit(1)
}

func Printf(format string, a ...interface{}) {
	fmt.Fprintf(os.Stdout, format, a...)
}

func Println(format string, a ...interface{}) {
	fmt.Fprintf(os.Stdout, format+"\n", a...)
}

func sqlite3Version(db *sql.DB) (string, error) {
	var version string
	err := db.QueryRow("SELECT SQLITE_VERSION()").Scan(&version)
	if err != nil {
		return "", err
	}
	return version, nil
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

func listTables(db *sql.DB) {
	// Query all table names in the database from sqlite_master
	rows, err := db.Query(`SELECT name FROM sqlite_master WHERE type='table'`)
	if err != nil {
		Printf("Failed to fetch tables: %s\n", err)
		return
	}
	defer rows.Close()

	//fmt.Println("Tables in the database:")
	for rows.Next() {
		var tableName string
		if err := rows.Scan(&tableName); err != nil {
			Printf("Failed to scan table name: %s\n", err)
			return
		}
		Println(tableName)
	}

	// Check for errors from iterating over rows.
	if err := rows.Err(); err != nil {
		Printf("Failed during iteration: %s\n", err)
	}
}

//---

func getLastProcessedIDDb(db *sql.DB) int {
	var lastID int
	err := db.QueryRow("SELECT COALESCE(MAX(rowid), 0) FROM procs").Scan(&lastID)
	if err != nil {
		Errorf("Failed to get the last processed ID: %v\n", err)
	}
	return lastID
}

func markIPAsProcessed(db *sql.DB, id int) {
	_, err := db.Exec("INSERT INTO procs(rowid) VALUES (?)", id)
	if err != nil {
		Errorf("Failed to mark IP as processed: %v\n", err)
	}
}

// func listNewIPDb(db *sql.DB) {
func procIps(db *sql.DB) {
	lastID := getLastProcessedIDDb(db)

	rows, err := db.Query("SELECT rowid, Name FROM ips WHERE rowid > ?", lastID)
	if err != nil {
		Errorf("Failed to query new IPs: %v\n", err)
	}

	// Store new IPs to process later
	type ipInfo struct {
		id        int
		ipAddress string
	}
	var newIPs []ipInfo

	for rows.Next() {
		var id int
		var ipAddress string
		if err := rows.Scan(&id, &ipAddress); err != nil {
			Printf("Failed to scan row: %v", err)
			continue
		}
		newIPs = append(newIPs, ipInfo{id: id, ipAddress: ipAddress})
	}

	// Close rows as soon as you're done iterating
	rows.Close()

	// Check for errors from iterating over rows.
	if err := rows.Err(); err != nil {
		Errorf("Failed during rows iteration: %v\n", err)
	}

	// Now process the IPs after closing the rows
	for _, info := range newIPs {
		Printf("New IP: %s\n", info.ipAddress)

		markIPAsProcessed(db, info.id)

		iptablesAllow(info.ipAddress)

		postfixAllow(info.ipAddress)

	}
}

//---
//---
//---

func listDataRows(db *sql.DB, table string) {

	rows, err := db.Query("SELECT rowid, Name, Data, Timestamp FROM " + table)
	if err != nil {
		Errorf("Failed to query: %v\n", err)
	}
	defer rows.Close()

	for rows.Next() {
		var rowid int
		var name, data, timestamp string
		if err := rows.Scan(&rowid, &name, &data, &timestamp); err != nil {
			Printf("Failed to scan row: %v", err)
			continue
		}
		Printf("%s\t%s\t[%d]%s\n", name, data, rowid, timestamp)
	}

	// Check for errors from iterating over rows.
	if err := rows.Err(); err != nil {
		Errorf("Failed during rows iteration: %v\n", err)
	}
}

func listProcs(db *sql.DB) {
	rows, err := db.Query("SELECT rowid,* FROM procs")
	if err != nil {
		Errorf("Failed to query ips: %v\n", err)
	}
	defer rows.Close()

	//fmt.Println("ips in the database:")
	//fmt.Println("Ip\tData\tTimestamp")
	for rows.Next() {
		var rowid int
		var name, data, timestamp sql.NullString
		if err := rows.Scan(&rowid, &name, &data, &timestamp); err != nil {
			Printf("Failed to scan row: %v", err)
			continue
		}
		Printf("%d\t%s\t%s\t%s\n", rowid, name.String, data.String, timestamp.String)
	}

	// Check for errors from iterating over rows.
	if err := rows.Err(); err != nil {
		Errorf("Failed during rows iteration: %v\n", err)
	}
}

func insertIdData(db *sql.DB, table string, rowid int, name string, data string) error {

	query := `INSERT INTO ` + table + ` (rowid,name,data) VALUES (?,?,?)`
	_, err := db.Exec(query, rowid, name, data)
	if err != nil {
		return fmt.Errorf("failed to insert into %s: %v", table, err)
	}

	return nil
}

func insertNameData(db *sql.DB, table string, name string, data string) error {

	query := `INSERT INTO ` + table + ` (name,data) VALUES (?,?)`
	_, err := db.Exec(query, name, data)
	if err != nil {
		return fmt.Errorf("failed to insert name into %s: %v", table, err)
	}

	return nil
}

func updateNameTime(db *sql.DB, table string, name string, time string) error {
	query := `UPDATE ` + table + ` SET Timestamp = ? WHERE Name = ?`
	_, err := db.Exec(query, time, name)
	if err != nil {
		return fmt.Errorf("failed to update timestamp for name %s in %s: %v", name, table, err)
	}
	return nil
}

func delName(db *sql.DB, table string, name string) error {

	query := `DELETE FROM ` + table + ` WHERE name = ?`
	result, err := db.Exec(query, name)
	if err != nil {
		return fmt.Errorf("failed to delete name from %s: %v", table, err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get affected rows: %v", err)
	}

	if rowsAffected == 0 {
		//return "No rows were deleted."
		return fmt.Errorf("No rows were deleted.")
	}

	//return fmt.Sprintf("success")
	return nil
}

func getTableRows(db *sql.DB, table string) ([]map[string]interface{}, error) {
	rows, err := db.Query(fmt.Sprintf("SELECT * FROM %s", table))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	columns, err := rows.Columns()
	if err != nil {
		return nil, err
	}

	values := make([]interface{}, len(columns))
	scanArgs := make([]interface{}, len(values))
	for i := range values {
		scanArgs[i] = &values[i]
	}

	var result []map[string]interface{}
	for rows.Next() {
		if err = rows.Scan(scanArgs...); err != nil {
			return nil, err
		}

		row := make(map[string]interface{})
		for i, col := range columns {
			value := values[i]
			byteValue, ok := value.([]byte)
			if ok {
				value = string(byteValue)
			}
			row[col] = value
		}
		result = append(result, row)
	}

	return result, nil
}

func getColumnRowsId(db *sql.DB, table string, rowid int) ([]string, []interface{}, error) {
	// Prepare the query statement
	query := "SELECT rowid,* FROM " + table + " WHERE rowid = ?"
	rows, err := db.Query(query, rowid)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()

	// Get the column names
	columnNames, err := rows.Columns()
	if err != nil {
		return nil, nil, err
	}

	// Prepare a slice of interface{} to hold the values
	values := make([]interface{}, len(columnNames))
	scanArgs := make([]interface{}, len(columnNames))
	for i := range values {
		scanArgs[i] = &values[i]
	}

	// Iterate through the rows and scan the values
	if rows.Next() {
		err = rows.Scan(scanArgs...)
		if err != nil {
			return nil, nil, err
		}
	} else {
		return nil, nil, sql.ErrNoRows
	}

	return columnNames, values, nil
}

func deleteId(db *sql.DB, table string, rowid int) error {

	query, err := db.Exec("DELETE FROM "+table+" WHERE rowid = ?", rowid)
	if err != nil {
		return err
	}

	rowsAffected, err := query.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return errors.New("delete failed")
	}

	return err
}

func truncateTable(db *sql.DB, table string) error {

	query, err := db.Exec("DELETE FROM " + table)
	if err != nil {
		return err
	}

	rowsAffected, err := query.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return errors.New("truncate failed")
	}

	return err
}

//	func ipAllow(ip string, tcpPort int) {
//	   cmd := fmt.Sprintf("iptables -I INPUT -s %s -p tcp --dport %d -j ACCEPT", ip, tcpPort)
func iptablesAllow(ip string) {
	cmd := fmt.Sprintf("/usr/sbin/iptables -I INPUT -s %s -j ACCEPT", ip)
	err := exec.Command("bash", "-c", cmd).Run()
	if err != nil {
		fmt.Println("Failed iptables: ", err)
		return
	}
	fmt.Println(cmd)
}

func postfixAllow(ip string) {
	/*
		/etc/postfix/client_access
		192.168.1.101 OK
		postmap /etc/postfix/client_access
		systemctl reload postfix
	*/

	filePath := "/etc/postfix/client_access"
	//content := "192.168.1.101 OK\n"

	content := ip + " OK\n"

	// Open the file for appending. If the file does not exist, create it.
	file, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening file: %v\n", err)
		return
	}
	defer file.Close()

	// Write the content to the file.
	if _, err := file.WriteString(content); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing to file: %v\n", err)
		return
	}

	fmt.Println("Postfix appended " + ip + " successfully!")

	//postmap file
	postmap := exec.Command("/usr/sbin/postmap", filePath)
	err_postmap := postmap.Run()
	if err_postmap != nil {
		fmt.Println("Failed postmap:", err_postmap)
		return
	}
	fmt.Println("Postmap " + filePath + " success.")

	//reload postfix
	reload := exec.Command("/usr/bin/systemctl", "reload", "postfix")
	err_reload := reload.Run()
	if err_reload != nil {
		fmt.Println("Failed systemctl reload postfix:", err_reload)
		return
	}
	fmt.Println("Postfix reload success")

	//cmd := fmt.Sprintf("iptables -I INPUT -s %s -j ACCEPT", ip)
	//exec.Command("bash", "-c", cmd).Run()
	//Println("postfix allow")
}

//---

func decryptName(base64Ciphertext string, base64Iv string, key string) error {

	//key := []byte("mysecretpassword")

	unBase64Ciphertext, err := base64.StdEncoding.DecodeString(base64Ciphertext)
	if err != nil {
		return err
	}

	unBase64Iv, err := base64.StdEncoding.DecodeString(base64Iv)
	if err != nil {
		return err
	}

	decrypted, err := aesDecrypt(unBase64Ciphertext, []byte(key), unBase64Iv)
	if err != nil {
		return err
	}

	fmt.Println(string(decrypted)) // Convert byte array to string here

	return nil
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

func genToken(db *sql.DB) error {
	//func genToken() error {

	reader := bufio.NewReader(os.Stdin)

	// Get username
	fmt.Print("Enter username: ")
	bekenUser, _ := reader.ReadString('\n')
	bekenUser = strings.TrimSpace(bekenUser)

	// Get password without echoing it
	fmt.Print("Enter password: ")
	passwordBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		//fmt.Println("\nError reading password:", err)
		return err
	}
	newBekenPass := string(passwordBytes)
	fmt.Println() // Newline for better formatting

	// Generate token
	text := bekenUser + ":" + newBekenPass
	data := []byte(text)
	hasher := sha256.New()
	hasher.Write(data)
	hashedData := hasher.Sum(nil)

	// Base64 encode
	base64Encoded := base64.StdEncoding.EncodeToString(hashedData)

	// Prepend "bt-" to base64 encoded string
	bekenToken := "bt-" + base64Encoded

	//fmt.Println("Generated beken_token:", bekenToken)

	// Generate AES-GCM encryption key (for demonstration using a 16 byte key)
	//key := []byte("1234567890123456") // This is just an example key; you'll want to replace it

	// Generate a random 32-byte key for AES-256
	//key := make([]byte, 32)
	//if _, err := io.ReadFull(rand.Reader, key); err != nil {
	//	panic(err.Error())
	//}

	key_random16, err := randomString(16)
	if err != nil {
		//fmt.Printf("Failed to generate random: %v\n", err)
		return err
	}

	// Convert string to []byte
	key_random16Bytes := []byte(key_random16)

	//iv, ciphertext := aesEncrypt([]byte(newBekenPass), key)
	iv, ciphertext := aesEncrypt([]byte(newBekenPass), key_random16Bytes)
	ivBase64 := base64.StdEncoding.EncodeToString(iv)
	ciphertextBase64 := base64.StdEncoding.EncodeToString(ciphertext)
	//fmt.Println("Encrypted data:", ciphertextBase64+" "+ivBase64)
	//fmt.Println("Key:", key_random16)

	// insert into db

	//add new token to db
	// Insert into the database
	_, err_insert_token := db.Exec("INSERT INTO tokens (Name, Data) VALUES (?, ?)", bekenToken, bekenUser)
	if err_insert_token != nil {
		return err_insert_token
	}
	//log.Printf("Isert tokens Name %s Data %s \n", bekenToken, bekenUser)

	// Save to the database
	result, err := db.Exec("INSERT INTO keys (Name, Data) VALUES (?, ?)", key_random16, bekenToken)
	if err != nil {
		return err
	}

	// Get last inserted ID
	lastID, err := result.LastInsertId()
	if err != nil {
		return err
	}

	// Convert lastID from int64 to int
	idInt := int(lastID)

	cryptData := ciphertextBase64 + " " + ivBase64
	userData := bekenUser

	// Insert into the database
	//_, err_query := db.Exec("INSERT INTO crypts (Name, Data) VALUES (?, ?)", cryptData, userData)
	_, err_query := db.Exec("INSERT INTO crypts (rowid, Name, Data) VALUES (?, ?, ?)", idInt, cryptData, userData)
	if err_query != nil {
		log.Printf("Failed to insert into database: %v\n", err_query)
		return err_query
	}
	//log.Printf("Isert crypts Name %s Data %s \n", cryptData, userData)

	fmt.Println("Generated beken_token:", bekenToken)
	return nil
}

// aesEncrypt encrypts plaintext using AES-GCM mode with a given key.
// It returns the IV and the ciphertext.
func aesEncrypt(plaintext, key []byte) ([]byte, []byte) {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	// Generate a random IV of 12 bytes
	iv := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err.Error())
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	ciphertext := aesgcm.Seal(nil, iv, plaintext, nil)
	return iv, ciphertext
}

func randomString(length int) (string, error) {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

//---

// db.Exec("PRAGMA journal_mode=WAL;")
