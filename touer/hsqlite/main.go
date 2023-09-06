package main

import (
	"crypto/md5"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"time"
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

func getHashFromFile(filePath string) (string, error) {
	bytes, err := ioutil.ReadFile(filePath)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

func saveHashToFile(filePath, hash string) error {
	return ioutil.WriteFile(filePath, []byte(hash), 0644)
}

func main() {
	//dbPath := "sqlite3.db"
	//hashFile := "hash.log"

	dbPath := os.Args[1]
	hashFile := os.Args[2]

	prevHash, err := getHashFromFile(hashFile)
	if err != nil {
		log.Fatal("Error reading initial hash: ", err)
	}

	for {
		curHash, err := calculateFileHash(dbPath)
		if err != nil {
			log.Fatal("Error calculating current hash: ", err)
		}

		if curHash != prevHash {
			fmt.Println("Database has changed.")
			err = saveHashToFile(hashFile, curHash)
			if err != nil {
				log.Fatal("Error saving new hash: ", err)
			}
			prevHash = curHash
		} else {
			fmt.Println("Database has not changed.")
		}

		time.Sleep(1 * time.Second)
	}
}
