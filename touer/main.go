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

var version = "1.0.0.🐕-2023-08-31"

func usage() string {

	usage := `Usage: ` + os.Args[0] + ` </path/db> [option]

  --help|-help|help           Display this help message
  --version|-version|version  Display version

Options:

<db>  list-tables

<db>  list-tokens
<db>  add-token token data
<db>  set-token-time token 2021-01-01T16:20:00Z
<db>  del-token token
<db>  purge-tokens

<db>  gen-token

<db>  list-keys
<db>  add-key n name data
<db>  del-key name
<db>  purge-keys

<db>  list-crypts
<db>  add-crypt n name data
<db>  del-crypt name
<db>  de-crypt name iv key
<db>  purge-crypts

<db>  list-configs
<db>  add-config name json
<db>  del-config name
<db>  purge-configs

<db>  list-ips
<db>  add-ip ip data
<db>  del-ip ip
<db>  purge-ips

<db>  proc-ips
<db>  list-procs
<db>  del-proc n
<db>  purge-procs

<db>  proc-crypts
<db>  list-tombs
<db>  del-tomb n
<db>  purge-tombs

iptables-allow ip
postfix-allow ip

postfix-passwd user pass
dovecot-passwd user pass

<db> postfix-passwd user
<db> dovecot-passwd user

<db> latest-passwd user

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
	case "iptables-allow":
		iptablesAllow(os.Args[2])
		return
	case "postfix-allow":
		postfixAllow(os.Args[2])
		return

	case "postfix-passwd":
		postfixPasswdFile(os.Args[2], os.Args[3])
		return

	case "dovecot-passwd":
		dovecotPasswdFile(os.Args[2], os.Args[3])
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

		case "list-tombs":
			listTombs(db)

		case "proc-ips":
			//listNewIPDb(db)
			procIps(db)

		case "proc-crypts":
			procCrypts(db)

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
			decrypted, err := decryptB64Cypher(name, iv, key)
			if err != nil {
				Errorf("Failed to purge: %v\n", err)
			}
			fmt.Println(decrypted)

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

		case "del-tomb":
			tomb := os.Args[3]
			n, err := strconv.Atoi(tomb)
			if err != nil {
				Errorf("Error converting rowid to integer: %v\n", err)
			}

			del := deleteId(db, "tombs", n)
			if del != nil {
				Errorf("Failed to del: %v\n", del)
			}

		case "purge-procs":
			err := truncateTable(db, "procs")
			if err != nil {
				Errorf("Failed to purge: %v\n", err)
			}

		case "purge-tombs":
			err := truncateTable(db, "tombs")
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

		case "postfix-passwd":
			setPostfixPasswd(db, os.Args[3])

		case "dovecot-passwd":
			setDovecotPasswd(db, os.Args[3])

		case "latest-passwd":
			passwd := getLatestPasswd(db, os.Args[3])
			fmt.Println(passwd)

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

func getLastProcessedProcID(db *sql.DB) int {
	var lastID int
	err := db.QueryRow("SELECT COALESCE(MAX(rowid), 0) FROM procs").Scan(&lastID)
	if err != nil {
		Errorf("Failed to get the last processed ID: %v\n", err)
	}
	return lastID
}

func getLastProcessedCryptID(db *sql.DB) int {
	var lastID int
	err := db.QueryRow("SELECT COALESCE(MAX(rowid), 0) FROM tombs").Scan(&lastID)
	if err != nil {
		Errorf("Failed to get the last processed ID: %v\n", err)
	}
	return lastID
}

func getRowCountAndTimeStamp(db *sql.DB, table string) (int, string) {
	var lastID int
	var TimeStamp string
	err := db.QueryRow("SELECT count(*), max(timestamp) FROM "+table).Scan(&lastID, &TimeStamp)
	if err != nil {
		Errorf("Failed to get the last processed ID: %v\n", err)
	}
	return lastID, TimeStamp
}

func getRowCount(db *sql.DB, table string) int {
	var lastID int
	//var TimeStamp string
	//err := db.QueryRow("SELECT count(*), max(timestamp) FROM " + table).Scan(&lastID, &TimeStamp)
	err := db.QueryRow("SELECT count(*) FROM " + table).Scan(&lastID)
	if err != nil {
		Errorf("Failed to get the last processed ID: %v\n", err)
	}
	return lastID
}

func markIPsProcessed(db *sql.DB, id int) {
	_, err := db.Exec("INSERT INTO procs(rowid) VALUES (?)", id)
	if err != nil {
		Errorf("Failed to mark IP as processed: %v\n", err)
	}
}

func markCryptsProcessed_V2(db *sql.DB, cryptID int) {
	stmt, err := db.Prepare("UPDATE tombs SET processed = 1 WHERE rowid = ?")
	if err != nil {
		Errorf("Failed to prepare statement: %v\n", err)
	}
	defer stmt.Close()

	_, err = stmt.Exec(cryptID)
	if err != nil {
		Errorf("Failed to execute statement: %v\n", err)
	}
}

func markCryptsProcessed(db *sql.DB, id int) {
	_, err := db.Exec("INSERT INTO tombs(rowid) VALUES (?)", id)
	if err != nil {
		Errorf("Failed to mark Crypt as processed: %v\n", err)
	}
}

func procCrypts(db *sql.DB) {
	lastID := getLastProcessedCryptID(db)
	//Printf("Crypt lastID: %d\n", lastID)

	rows, err := db.Query("SELECT rowid, Data FROM crypts WHERE rowid > ?", lastID)
	if err != nil {
		Errorf("Failed to query: %v\n", err)
	}

	// Store new Crypts to process later
	type cryptInfo struct {
		id       int
		username string
	}
	var newCrypts []cryptInfo

	for rows.Next() {
		var id int
		var username string
		if err := rows.Scan(&id, &username); err != nil {
			Printf("Failed to scan row: %v", err)
			continue
		}
		newCrypts = append(newCrypts, cryptInfo{id: id, username: username})
	}

	// Close rows as soon as you're done iterating
	rows.Close()

	// Check for errors from iterating over rows.
	if err := rows.Err(); err != nil {
		Errorf("Failed during rows iteration: %v\n", err)
	}

	// Now process the Crypts after closing the rows
	var count int
	for _, info := range newCrypts {
		fmt.Printf("New Crypt: %d %s\n", info.id, info.username)
		markCryptsProcessed(db, info.id)

		setPostfixPasswd(db, info.username)
		setDovecotPasswd(db, info.username)

		count++
	}

	if count > 0 {
		fmt.Println("Processed", count, "rows")

		postfixPostMapReload("/etc/postfix/sasl_passwd")
		dovecotRestart()
	}

}

func procIps(db *sql.DB) {
	lastID := getLastProcessedProcID(db)
	//Printf("Crypt lastID: %d\n", lastID)

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

		markIPsProcessed(db, info.id)

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

func listTombs(db *sql.DB) {
	rows, err := db.Query("SELECT rowid,* FROM tombs")
	if err != nil {
		Errorf("Failed to query crypts: %v\n", err)
	}
	defer rows.Close()

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

func iptablesAllow(ip string) {
	// Fetch existing rules
	cmd := exec.Command("bash", "-c", "/usr/sbin/iptables -vnL INPUT")
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Println("Failed to fetch iptables rules: ", err)
		return
	}

	// Check if IP exists in current rules
	if strings.Contains(string(output), ip) {
		fmt.Println("IP already exists in iptables rules.")
		return
	}

	// Add new rule if IP doesn't exist
	cmdStr := fmt.Sprintf("/usr/sbin/iptables -I INPUT -s %s -j ACCEPT", ip)
	err = exec.Command("bash", "-c", cmdStr).Run()
	if err != nil {
		fmt.Println("Failed iptables: ", err)
		return
	}
	fmt.Println(cmdStr)
}

func dovecotRestart() {

	//restart dovecote
	restart := exec.Command("/usr/bin/systemctl", "restart", "dovecot")
	err_restart := restart.Run()
	if err_restart != nil {
		fmt.Println("Failed systemctl restart dovecot:", err_restart)
		return
	}
	fmt.Println("Dovecot restart success")

}

func postfixPostMapReload(filePath string) {
	//postfix admin...

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
}

//	func ipAllow(ip string, tcpPort int) {
//	   cmd := fmt.Sprintf("iptables -I INPUT -s %s -p tcp --dport %d -j ACCEPT", ip, tcpPort)
func iptablesAllow_V1(ip string) {
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
	content := ip + " OK\n"

	// Check if IP already exists in the file
	existingFile, err := os.Open(filePath)
	if err == nil { // No error means file exists
		defer existingFile.Close()

		scanner := bufio.NewScanner(existingFile)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, ip+" ") {
				fmt.Fprintf(os.Stderr, "IP exists in file: %s\n", ip)
				return
			}
		}
		if err := scanner.Err(); err != nil {
			fmt.Fprintf(os.Stderr, "Error reading file: %v\n", err)
			return
		}
	}

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

	//postfix admin...

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

}

func postfixAllow_V1(ip string) {
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
	//result, err := db.Exec("INSERT INTO keys (Name, Data) VALUES (?, ?)", key_random16, bekenToken)
	result, err := db.Exec("INSERT INTO keys (Name, Data) VALUES (?, ?)", key_random16, bekenUser)
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

func decryptB64Cypher(base64Ciphertext string, base64Iv string, key string) (string, error) {

	//key := []byte("mysecretpassword")

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

func postfixPasswdFile(username string, password string) {
	// Get username and password from command line arguments
	//username := os.Args[1]
	//password := os.Args[2]

	// Open the file for reading
	filePath := "/etc/postfix/sasl_passwd"
	file, err := os.Open(filePath)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer file.Close()

	// Read the file line by line
	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		fmt.Println("Error reading file:", err)
		return
	}

	// Flag to check if user exists
	userExists := false

	// Update the file content
	for i, line := range lines {
		fields := strings.Fields(line)
		if len(fields) > 0 && fields[0] == username {
			lines[i] = fmt.Sprintf("%s %s", username, password)
			userExists = true
			break
		}
	}

	// If user doesn't exist, append new line
	if !userExists {
		lines = append(lines, fmt.Sprintf("%s %s", username, password))
	}

	// Open file for writing
	outFile, err := os.Create(filePath)
	if err != nil {
		fmt.Println("Error creating file:", err)
		return
	}
	defer outFile.Close()

	// Write the updated content back to the file
	writer := bufio.NewWriter(outFile)
	for _, line := range lines {
		_, err := writer.WriteString(line + "\n")
		if err != nil {
			fmt.Println("Error writing to file:", err)
			return
		}
	}
	writer.Flush()
}

func dovecotPasswdFile(username string, password string) {
	// Get username and password from command line arguments
	//username := os.Args[1]
	//password := os.Args[2]

	// Open the file for reading
	filePath := "/etc/dovecot/dovecot-users"
	file, err := os.Open(filePath)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer file.Close()

	// Read the file line by line
	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		fmt.Println("Error reading file:", err)
		return
	}

	// Flag to check if user exists
	userExists := false

	// Update the file content
	for i, line := range lines {
		fields := strings.SplitN(line, ":{PLAIN}", 2)
		if len(fields) > 0 && fields[0] == username {
			lines[i] = fmt.Sprintf("%s:{PLAIN}%s", username, password)
			userExists = true
			break
		}
	}

	// If user doesn't exist, append new line
	if !userExists {
		lines = append(lines, fmt.Sprintf("%s:{PLAIN}%s", username, password))
	}

	// Open file for writing
	outFile, err := os.Create(filePath)
	if err != nil {
		fmt.Println("Error creating file:", err)
		return
	}
	defer outFile.Close()

	// Write the updated content back to the file
	writer := bufio.NewWriter(outFile)
	for _, line := range lines {
		_, err := writer.WriteString(line + "\n")
		if err != nil {
			fmt.Println("Error writing to file:", err)
			return
		}
	}
	writer.Flush()
}

func setPostfixPasswd(db *sql.DB, username string) {
	passwd := getLatestPasswd(db, username)
	postfixPasswdFile(username, passwd)
	fmt.Println("set " + username + " /etc/postfix/sasl_passwd")
}

func setDovecotPasswd(db *sql.DB, username string) {
	passwd := getLatestPasswd(db, username)
	dovecotPasswdFile(username, passwd)
	fmt.Println("set " + username + " /etc/dovecot/dovecot-users")
}

func getLatestPasswd(db *sql.DB, username string) string {
	// Initialize a variable to hold the retrieved Name value
	var rowid int
	var name_crypt string
	var name_key string

	// Run the SQL query
	err1 := db.QueryRow("SELECT rowid,name FROM crypts WHERE data = ? ORDER BY timestamp DESC LIMIT 1", username).Scan(&rowid, &name_crypt)

	// Check for errors from the query
	if err1 != nil {
		if err1 == sql.ErrNoRows {
			// Handle no rows case (i.e., no matching username found)
			fmt.Printf("No rows found for username: %s\n", username)
		} else {
			// Handle other types of errors
			fmt.Printf("Failed to execute query: %v\n", err1)
		}
		return ""
	}

	// At this point, `name` contains the most recent Name value for the given username
	// You can now proceed to use `name` to set the postfix password or perform other operations
	//fmt.Printf("Latest name_crypt for %s is: %s rowid: %d\n", username, name_crypt, rowid)

	// Run the SQL query
	err2 := db.QueryRow("SELECT name FROM keys WHERE rowid = ?", rowid).Scan(&name_key)

	// Check for errors from the query
	if err2 != nil {
		if err2 == sql.ErrNoRows {
			// Handle no rows case (i.e., no matching username found)
			fmt.Printf("No rows found for username: %s\n", username)
		} else {
			// Handle other types of errors
			fmt.Printf("Failed to execute query: %v\n", err2)
		}
		return ""
	}
	//fmt.Printf("name_key %s is: %s rowid: %d\n", username, name_key, rowid)

	//decryptB64Cypher(b64cyphertxt, b64iv, key)

	splitted := strings.Split(name_crypt, " ") // Splitting by single space

	crypt := splitted[0]
	iv := splitted[1]

	decrypted, err_decrypt := decryptB64Cypher(crypt, iv, name_key)
	if err_decrypt != nil {
		fmt.Printf("Failed decrypt: %v\n", err_decrypt)
		return ""
	}
	//fmt.Println(decrypted)
	return decrypted
}

// db.Exec("PRAGMA journal_mode=WAL;")
/*













 */
