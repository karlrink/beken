package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func main() {
	// Check if the required number of arguments are provided
	if len(os.Args) < 3 {
		fmt.Println("Usage: " + os.Args[0] + " <username> <password>")
		fmt.Println("\nEdits: /etc/postfix/sasl_passwd")
		return
	}

	// Get username and password from command line arguments
	username := os.Args[1]
	password := os.Args[2]

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
