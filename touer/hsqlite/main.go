package main

import (
	"crypto/md5"
	"fmt"
	"io"
	"log"
	"os"
	//_ "github.com/mattn/go-sqlite3"
)

func calculateFileHash(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := md5.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}

func main() {
	dbPath := "your_database.db"
	// Open the SQLite database.
	//db, err := sql.Open("sqlite3", dbPath)
	//if err != nil {
	//	log.Fatal(err)
	//}
	//defer db.Close()

	// Calculate the initial hash of the database file.
	initialHash, err := calculateFileHash(dbPath)
	if err != nil {
		log.Fatal(err)
	}

	// Perform your insert or update operation here.
	// For example, you can use db.Exec() to execute SQL statements.

	// Calculate the hash of the database file after the operation.
	updatedHash, err := calculateFileHash(dbPath)
	if err != nil {
		log.Fatal(err)
	}

	// Compare the initial and updated hashes to detect changes.
	if initialHash != updatedHash {
		fmt.Println("Database has changed due to insert or update.")
	} else {
		fmt.Println("Database has not changed.")
	}
}
