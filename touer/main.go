package main

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"

	_ "github.com/mattn/go-sqlite3"
)

var version = "0.0.0.dev-0"

func usage() string {

	usage := `Usage: ` + os.Args[0] + ` </path/db> [option]

  --help|-help|help           Display this help message
  --version|-version|version  Display version

Options:

  list-tables

  proc-ips

  list-procs
  del-proc n
  purge-procs

  list-ips
  add-ip ip data
  del-ip ip
  purge-ips

  list-tokens
  add-token token data
  del-token token
  purge-tokens

  list-configs
  add-config name json
  del-config name
  purge-configs


`
	return usage
}

func main() {

	if len(os.Args) < 2 {
		printErr(usage())
	}

	switch os.Args[1] {
	case "--help", "-help", "help":
		printErr(usage())
	case "--version", "-version", "version":
		printOut("Version: " + version)
		sqlite3version, err := getSqlite3Version(os.Args[1])
		if err != nil {
			printErr("Failed to get SQLite version: %v", err)
		}
		printOut("Sqlite3: " + sqlite3version)
		return
	}

	dbFile := os.Args[1]

	// Check if the file exists
	if _, err := os.Stat(dbFile); os.IsNotExist(err) {
		printErr("File not found: %s\n", dbFile)
	}
	// Connect to the SQLite3 database file
	db, err := sql.Open("sqlite3", dbFile)
	if err != nil {
		printErr("Failed to connect: %s\n", err)
	}
	defer db.Close()

	// Check if the database connection is valid by pinging it
	if err := db.Ping(); err != nil {
		printErr("Failed to ping the database: %v\n", err)
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
				printErr("Failed to insert: %v", err)
			}
		case "add-token":
			token := os.Args[3]
			data := os.Args[4]
			err := insertNameData(db, "tokens", token, data)
			if err != nil {
				printErr("Failed to insert: %v", err)
			}

		case "del-ip":
			ip := os.Args[3]
			err := delName(db, "ips", ip)
			if err != nil {
				printErr("Failed to del: %v", err)
			}

		case "del-token":
			token := os.Args[3]
			err := delName(db, "tokens", token)
			if err != nil {
				printErr("Failed to del: %v", err)
			}

		case "del-proc":
			proc := os.Args[3]
			n, err := strconv.Atoi(proc)
			if err != nil {
				printErr("Error converting rowid to integer: %v", err)
			}

			del := deleteId(db, "procs", n)
			if del != nil {
				printErr("Failed to del: %v", del)
			}

		case "purge-procs":
			err := truncateTable(db, "procs")
			if err != nil {
				printErr("Failed to purge: %v", err)
			}

		case "purge-ips":
			err := truncateTable(db, "ips")
			if err != nil {
				printErr("Failed to purge: %v", err)
			}

		case "purge-tokens":
			err := truncateTable(db, "tokens")
			if err != nil {
				printErr("Failed to purge: %v", err)
			}

		default:
			printOut("Invalid argument: " + os.Args[2])
		}
		return
	}

	printOut(`{"sqlite3":true}`)

	//fmt.Println(usage())
	//dbFile := os.Args[1]
	// List new rows from the ips table
	//listNewIPIds(db)
	//listNewIPTms(db)
	//listNewIPDb(db)
}

func printErr(format string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", a...)
	os.Exit(1)
}

func printOut(format string, a ...interface{}) {
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

func getRowId(db *sql.DB, table string, rowid int) ([]string, []interface{}, error) {
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
