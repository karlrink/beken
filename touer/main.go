package main

import (
  "database/sql"
  "fmt"
  "log"
  "os"
  "time"

  "io/ioutil"
  "strconv"

  _ "github.com/mattn/go-sqlite3"
)



const cacheFileName = "last_processed_id.txt"

func main() {
	if len(os.Args) < 2 {
		log.Fatal("Usage: <program_name> <path_to_db>")
	}

	dbPath := os.Args[1]

	// Check if the file exists
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		log.Fatalf("File not found: %s", dbPath)
	}

	// Connect to the SQLite3 database file
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer db.Close()

	// List new rows from the ips table
	//listNewIPIds(db)
	//listNewIPTms(db)
	listNewIPDb(db)
}


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

    rows, err := db.Query("SELECT rowid, ip FROM ips WHERE rowid > ?", lastID)
    if err != nil {
        log.Fatalf("Failed to query new IPs: %v", err)
    }

    // Store new IPs to process later
    type ipInfo struct {
        id int
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
*/




//----

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


func listTokens(db *sql.DB) {
	rows, err := db.Query("SELECT Token, Data, Timestamp FROM tokens")
	if err != nil {
		log.Fatalf("Failed to query tokens: %v", err)
	}
	defer rows.Close()

	fmt.Println("Tokens in the database:")
	fmt.Println("Token\tData\tTimestamp")
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
    rows, err := db.Query("SELECT Ip, Data, Timestamp FROM ips")
    if err != nil {
        log.Fatalf("Failed to query ips: %v", err)
    }
    defer rows.Close()

    fmt.Println("ips in the database:")
    fmt.Println("Ip\tData\tTimestamp")
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





