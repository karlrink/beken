package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"

	_ "github.com/mattn/go-sqlite3"
)

var version = "0.0.0.dev-0"

func usage() string {

	usage := `Usage: ` + os.Args[0] + ` </path/db> [option]

  --help|-help|help           Display this help message
  --version|-version|version  Display version

Options:

  list-tables
  list-ips
  list-tokens
  list-procs

  proc-ips

  add-ip ip data
  del-ip ip

  add-token token data
  del-token token

  list-configs
  add-config name json
  del-config name

`
	return usage
}

func main() {

	if len(os.Args) < 2 {
		fmt.Println(usage())
		return
	}

	switch os.Args[1] {
	case "--help", "-help", "help":
		fmt.Println(usage())
		return
	case "--version", "-version", "version":
		fmt.Println("Version:", version)
		sqlite3version, err := getSqlite3Version(os.Args[1])
		if err != nil {
			log.Fatalf("Failed to get SQLite version: %v", err)
		}
		fmt.Println("Sqlite3:", sqlite3version)
		return
	}

	dbFile := os.Args[1]

	// Check if the file exists
	if _, err := os.Stat(dbFile); os.IsNotExist(err) {
		//log.Fatalf("File not found: %s", dbFile)
		fmt.Fprintf(os.Stderr, "File not found: %s\n", dbFile)
		return
	}
	// Connect to the SQLite3 database file
	db, err := sql.Open("sqlite3", dbFile)
	if err != nil {
		//log.Fatalf("Failed to connect: %v", err)
		//fmt.Fprintf("Failed to connect: %s", err)
		fmt.Printf("Failed to connect: %s\n", err)
		return
	}
	defer db.Close()

	// Check if the database connection is valid by pinging it
	if err := db.Ping(); err != nil {
		fmt.Printf("Failed to ping the database: %v\n", err)
		return
	}

	if len(os.Args) > 2 {

		switch os.Args[2] {
		case "list-tables":
			listTables(db)
		case "list-ips":
			listIps(db)
		case "list-tokens":
			listTokens(db)
		case "list-procs":
			listProcs(db)
		case "proc-ips":
			listNewIPDb(db)
		case "add-ip":
			ip := os.Args[3]
			data := os.Args[4]

			err := insertNameData(db, "ips", ip, data)
			if err != nil {
				log.Fatalf("Failed to insert IP: %v", err)
			}
		case "add-token":
			token := os.Args[3]
			data := os.Args[4]

			err := insertNameData(db, "tokens", token, data)
			if err != nil {
				log.Fatalf("Failed to insert IP: %v", err)
			}

		default:
			fmt.Println("Invalid argument: ", os.Args[2])
		}
		return
	}

	fmt.Println(`{"sqlite3":true}`)

	//fmt.Println(usage())
	//dbFile := os.Args[1]
	// List new rows from the ips table
	//listNewIPIds(db)
	//listNewIPTms(db)
	//listNewIPDb(db)
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

//func listTables(db *sql.DB) {
//	fmt.Println("listTables")
//}

func listTables(db *sql.DB) {
	// Query all table names in the database from sqlite_master
	rows, err := db.Query(`SELECT name FROM sqlite_master WHERE type='table'`)
	if err != nil {
		fmt.Printf("Failed to fetch tables: %s\n", err)
		return
	}
	defer rows.Close()

	//fmt.Println("Tables in the database:")
	for rows.Next() {
		var tableName string
		if err := rows.Scan(&tableName); err != nil {
			fmt.Printf("Failed to scan table name: %s\n", err)
			return
		}
		fmt.Println(tableName)
	}

	// Check for errors from iterating over rows.
	if err := rows.Err(); err != nil {
		fmt.Printf("Failed during iteration: %s\n", err)
	}
}

//---
//---
//---

func getLastProcessedIDDb(db *sql.DB) int {
	var lastID int
	err := db.QueryRow("SELECT COALESCE(MAX(rowid), 0) FROM procs").Scan(&lastID)
	if err != nil {
		log.Fatalf("Failed to get the last processed ID: %v", err)
	}
	return lastID
}

func markIPAsProcessed(db *sql.DB, id int) {

	_, err := db.Exec("INSERT INTO procs(rowid) VALUES (?)", id)
	if err != nil {
		log.Fatalf("Failed to mark IP as processed: %v", err)
	}
}

func listNewIPDb(db *sql.DB) {
	lastID := getLastProcessedIDDb(db)

	rows, err := db.Query("SELECT rowid, Name FROM ips WHERE rowid > ?", lastID)
	if err != nil {
		log.Fatalf("Failed to query new IPs: %v", err)
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
			log.Printf("Failed to scan row: %v", err)
			continue
		}
		newIPs = append(newIPs, ipInfo{id: id, ipAddress: ipAddress})
	}

	// Close rows as soon as you're done iterating
	rows.Close()

	// Check for errors from iterating over rows.
	if err := rows.Err(); err != nil {
		log.Fatalf("Failed during rows iteration: %v", err)
	}

	// Now process the IPs after closing the rows
	for _, info := range newIPs {
		fmt.Printf("New IP: %s\n", info.ipAddress)
		markIPAsProcessed(db, info.id)
	}
}

//---
//---
//---

//Failed to mark IP as processed: database is locked
/*
func listNewIPDb(db *sql.DB) {
	lastID := getLastProcessedIDDb(db)
	//rows, err := db.Query("SELECT id, ip_address FROM ips WHERE id > ?", lastID)
	rows, err := db.Query("SELECT rowid, ip FROM ips WHERE rowid > ?", lastID)
	if err != nil {
		log.Fatalf("Failed to query new IPs: %v", err)
	}
	defer rows.Close()

	for rows.Next() {
		var id int
		var ipAddress string
		if err := rows.Scan(&id, &ipAddress); err != nil {
			log.Printf("Failed to scan row: %v", err)
			continue
		}
		fmt.Printf("New IP: %s\n", ipAddress)
		markIPAsProcessed(db, id)
	}

	// Check for errors from iterating over rows.
	if err := rows.Err(); err != nil {
		log.Fatalf("Failed during rows iteration: %v", err)
	}
}

//----

const cacheFileName = "last_processed_id.txt"

func getLastProcessedTimestamp() time.Time {
	content, err := ioutil.ReadFile(cacheFileName)
	if err != nil {
		if os.IsNotExist(err) {
			return time.Time{}
		}
		log.Fatalf("Failed to read the cache file: %v", err)
	}

	parsedTime, err := time.Parse(time.RFC3339, string(content))
	if err != nil {
		log.Fatalf("Failed to parse timestamp from cache: %v", err)
	}

	return parsedTime
}

func updateCacheFile(timestamp time.Time) {
	timeStr := timestamp.Format(time.RFC3339)
	err := ioutil.WriteFile(cacheFileName, []byte(timeStr), 0644)
	if err != nil {
		log.Fatalf("Failed to update cache file: %v", err)
	}
}

func listNewIPTms(db *sql.DB) {
	lastTimestamp := getLastProcessedTimestamp()
	rows, err := db.Query("SELECT Ip, Timestamp FROM ips WHERE Timestamp > ?", lastTimestamp)
	if err != nil {
		log.Fatalf("Failed to query new IPs: %v", err)
	}
	defer rows.Close()

	var latestTimestamp time.Time = lastTimestamp
	for rows.Next() {
		var ip string
		var timestamp string

		if err := rows.Scan(&ip, &timestamp); err != nil {
			log.Printf("Failed to scan row: %v", err)
			continue
		}

		//rowTime, err := time.Parse("2006-01-02 15:04:05", timestamp)
		rowTime, err := time.Parse(time.RFC3339, timestamp)
		if err != nil {
			log.Printf("Failed to parse timestamp from row: %v", err)
			continue
		}

		if rowTime.After(latestTimestamp) {
			latestTimestamp = rowTime
		}

		fmt.Printf("New IP: %s (Timestamp: %s)\n", ip, timestamp)
	}

	// Update cache file with the latest timestamp
	if latestTimestamp.After(lastTimestamp) {
		updateCacheFile(latestTimestamp)
	}

	// Check for errors from iterating over rows.
	if err := rows.Err(); err != nil {
		log.Fatalf("Failed during rows iteration: %v", err)
	}
}

// -------

func getLastProcessedIDFile() int {
	content, err := ioutil.ReadFile(cacheFileName)
	if err != nil {
		if os.IsNotExist(err) {
			return 0
		}
		log.Fatalf("Failed to read the cache file: %v", err)
	}
	lastID, err := strconv.Atoi(string(content))
	if err != nil {
		log.Fatalf("Failed to convert content to integer: %v", err)
	}
	return lastID
}

func updateCacheFileId(id int) {
	err := ioutil.WriteFile(cacheFileName, []byte(strconv.Itoa(id)), 0644)
	if err != nil {
		log.Fatalf("Failed to update cache file: %v", err)
	}
}

func listNewIPIds(db *sql.DB) {
	lastID := getLastProcessedIDFile()
	rows, err := db.Query("SELECT rowid, ip FROM ips WHERE rowid > ?", lastID)
	if err != nil {
		log.Fatalf("Failed to query new IPs: %v", err)
	}
	defer rows.Close()

	var highestID int = lastID
	for rows.Next() {
		var id int
		var ipAddress string
		if err := rows.Scan(&id, &ipAddress); err != nil {
			log.Printf("Failed to scan row: %v", err)
			continue
		}
		if id > highestID {
			highestID = id
		}
		fmt.Printf("New IP: %s\n", ipAddress)
	}

	// Update cache file with the highest ID
	if highestID > lastID {
		updateCacheFileId(highestID)
	}

	// Check for errors from iterating over rows.
	if err := rows.Err(); err != nil {
		log.Fatalf("Failed during rows iteration: %v", err)
	}
}

// -------
*/

func listTokens(db *sql.DB) {
	rows, err := db.Query("SELECT Name, Data, Timestamp FROM tokens")
	if err != nil {
		log.Fatalf("Failed to query tokens: %v", err)
	}
	defer rows.Close()

	//fmt.Println("Tokens in the database:")
	//fmt.Println("Token\tData\tTimestamp")
	for rows.Next() {
		var token, data, timestamp string
		if err := rows.Scan(&token, &data, &timestamp); err != nil {
			log.Printf("Failed to scan row: %v", err)
			continue
		}
		fmt.Printf("%s\t%s\t%s\n", token, data, timestamp)
	}

	// Check for errors from iterating over rows.
	if err := rows.Err(); err != nil {
		log.Fatalf("Failed during rows iteration: %v", err)
	}
}

func listIps(db *sql.DB) {
	rows, err := db.Query("SELECT Name, Data, Timestamp FROM ips")
	if err != nil {
		log.Fatalf("Failed to query ips: %v", err)
	}
	defer rows.Close()

	//fmt.Println("ips in the database:")
	//fmt.Println("Ip\tData\tTimestamp")
	for rows.Next() {
		var ip, data, timestamp string
		if err := rows.Scan(&ip, &data, &timestamp); err != nil {
			log.Printf("Failed to scan row: %v", err)
			continue
		}
		fmt.Printf("%s\t%s\t%s\n", ip, data, timestamp)
	}

	// Check for errors from iterating over rows.
	if err := rows.Err(); err != nil {
		log.Fatalf("Failed during rows iteration: %v", err)
	}
}

func listProcs(db *sql.DB) {
	rows, err := db.Query("SELECT rowid,* FROM procs")
	if err != nil {
		log.Fatalf("Failed to query ips: %v", err)
	}
	defer rows.Close()

	//fmt.Println("ips in the database:")
	//fmt.Println("Ip\tData\tTimestamp")
	for rows.Next() {
		var rowid int
		var name, data, timestamp sql.NullString
		if err := rows.Scan(&rowid, &name, &data, &timestamp); err != nil {
			log.Printf("Failed to scan row: %v", err)
			continue
		}
		fmt.Printf("%d\t%s\t%s\t%s\n", rowid, name.String, data.String, timestamp.String)
	}

	// Check for errors from iterating over rows.
	if err := rows.Err(); err != nil {
		log.Fatalf("Failed during rows iteration: %v", err)
	}
}

func insertNameData(db *sql.DB, table string, name string, data string) error {

	query := `INSERT INTO ` + table + ` (name,data) VALUES (?,?)`
	_, err := db.Exec(query, name, data)
	if err != nil {
		return fmt.Errorf("failed to insert name into %s: %v", table, err)
	}

	return nil
}

func insertIpData(db *sql.DB, table string, ip string, data string) error {

	query := `INSERT INTO ` + table + ` (ip,data) VALUES (?,?)`
	_, err := db.Exec(query, ip, data)
	if err != nil {
		return fmt.Errorf("failed to insert IP into %s: %v", table, err)
	}

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

/*

func getIps(db *sql.DB) {
	ips, err := getTableRows(db, "ips")
	if err != nil {
		fmt.Println("Error getting IPs:", err)
		return
	}
	for _, ip := range ips {
		fmt.Println(ip["Ip"], ip["Data"], ip["Timestamp"])
	}
}

func getTokens(db *sql.DB) {
	tokens, err := getTableRows(db, "tokens")
	if err != nil {
		fmt.Println("Error getting Tokens:", err)
		return
	}
	for _, token := range tokens {
		fmt.Println(token["Token"], token["Data"], token["Timestamp"])
	}
}

func getConfigs(db *sql.DB) {
	configs, err := getTableRows(db, "configs")
	if err != nil {
		fmt.Println("Error getting Configs:", err)
		return
	}
	for _, config := range configs {
		fmt.Println(config["Name"], config["Data"], config["Timestamp"])
	}
}

*/

// db.Exec("PRAGMA journal_mode=WAL;")
