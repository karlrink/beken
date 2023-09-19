package main

import (
	"fmt"

	"ubeken/kes"
)

func main() {
	encryptionKey := "KEY321"
	plaintext := "Hello, World! KES"

	fmt.Println("Original Data:", plaintext)

	fmt.Println("XOR")
	encryptedData := kes.XorEncrypt(plaintext, encryptionKey)
	fmt.Println("Encrypted Data:", encryptedData)
	decryptedData := kes.XorDecrypt(encryptedData, encryptionKey)
	fmt.Println("Decrypted Data:", decryptedData)

	fmt.Println("VIGENERE")
	encryptedData = kes.VigenereEncrypt(plaintext, encryptionKey)
	fmt.Println("Encrypted Data:", encryptedData)
	decryptedData = kes.VigenereDecrypt(encryptedData, encryptionKey)
	fmt.Println("Decrypted Data:", decryptedData)

	fmt.Println("RAILFENCE")
	encryptedData = kes.EncryptRailFence(plaintext, len(encryptionKey))
	fmt.Println("Encrypted Data:", encryptedData)
	decryptedData = kes.DecryptRailFence(encryptedData, len(encryptionKey))
	fmt.Println("Decrypted Data:", decryptedData)

	fmt.Println("KES")
	encryptedData = kes.EncryptKES(plaintext, encryptionKey)
	fmt.Println("Encrypted Data:", encryptedData)
	decryptedData = kes.DecryptKES(encryptedData, encryptionKey)
	fmt.Println("Decrypted Data:", decryptedData)
}
