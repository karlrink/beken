package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

func xorEncrypt(plainText, keyStr string) string {
	plaintextBytes := []byte(plainText)
	keyBytes := []byte(keyStr)
	encryptedData := make([]byte, len(plaintextBytes))

	for i, byte := range plaintextBytes {
		keyByte := keyBytes[i%len(keyBytes)]
		encryptedData[i] = byte ^ keyByte
	}

	return base64.StdEncoding.EncodeToString(encryptedData)
}

func xorDecrypt(base64Cipher, keyStr string) string {
	cipherBytes, _ := base64.StdEncoding.DecodeString(base64Cipher)
	keyBytes := []byte(keyStr)
	decryptedData := make([]byte, len(cipherBytes))

	for i, byte := range cipherBytes {
		keyByte := keyBytes[i%len(keyBytes)]
		decryptedData[i] = byte ^ keyByte
	}

	return string(decryptedData)
}

func vigenereEncrypt(plainText, keyStr string) string {
	plaintextBytes := []byte(plainText)
	keyBytes := []byte(keyStr)
	encryptedData := make([]byte, len(plaintextBytes))

	for i, byte := range plaintextBytes {
		keyByte := keyBytes[i%len(keyBytes)]
		encryptedData[i] = byte + keyByte
	}

	return fmt.Sprintf("%x", encryptedData)
}

func vigenereDecrypt(hexCipher, keyStr string) string {
	hexCipherBytes, _ := hex.DecodeString(hexCipher)
	keyBytes := []byte(keyStr)
	decryptedData := make([]byte, len(hexCipherBytes))

	for i, hexByte := range hexCipherBytes {
		keyByte := keyBytes[i%len(keyBytes)]
		decryptedByte := byte((int(hexByte) - int(keyByte) + 256) % 256)
		decryptedData[i] = decryptedByte
	}

	return string(decryptedData)
}

func encryptRailFence(plainText string, numRails int) string {
	encodedPlainText := base64.StdEncoding.EncodeToString([]byte(plainText))
	rails := make([]string, numRails)
	railIndex := 0
	direction := 1

	for _, char := range encodedPlainText {
		rails[railIndex] += string(char)

		if railIndex == 0 {
			direction = 1
		} else if railIndex == numRails-1 {
			direction = -1
		}

		railIndex += direction
	}

	cipherText := ""
	for _, rail := range rails {
		cipherText += rail
	}

	return base64.StdEncoding.EncodeToString([]byte(cipherText))
}

func decryptRailFence(base64Cipher string, numRails int) string {
	cipherText, _ := base64.StdEncoding.DecodeString(base64Cipher)
	rails := make([][]byte, numRails)
	for i := 0; i < numRails; i++ {
		rails[i] = make([]byte, len(cipherText))
	}

	railIndex := 0
	direction := 1
	index := 0

	for i, _ := range cipherText {
		rails[railIndex][i] = '*'

		if railIndex == 0 {
			direction = 1
		} else if railIndex == numRails-1 {
			direction = -1
		}

		railIndex += direction
	}

	for i := 0; i < numRails; i++ {
		for j := 0; j < len(cipherText); j++ {
			if rails[i][j] == '*' && index < len(cipherText) {
				rails[i][j] = cipherText[index]
				index++
			}
		}
	}

	plainText := ""
	railIndex = 0
	direction = 1

	for i := 0; i < len(cipherText); i++ {
		plainText += string(rails[railIndex][i])

		if railIndex == 0 {
			direction = 1
		} else if railIndex == numRails-1 {
			direction = -1
		}

		railIndex += direction
	}

	decodedPlainText, _ := base64.StdEncoding.DecodeString(plainText)
	return string(decodedPlainText)
}

func encryptKES(plainText, keyStr string) string {
	order := 0

	for _, char := range keyStr {
		order += int(char)
	}
	order %= 2

	railFenceEncrypted := encryptRailFence(plainText, len(keyStr))

	if order == 0 {
		xorEncrypted := xorEncrypt(railFenceEncrypted, keyStr)
		encrypted := vigenereEncrypt(xorEncrypted, keyStr)
		return base64.StdEncoding.EncodeToString([]byte(encrypted))
	}

	vigenereEncrypted := vigenereEncrypt(railFenceEncrypted, keyStr)
	xorEncrypted := xorEncrypt(vigenereEncrypted, keyStr)

	return base64.StdEncoding.EncodeToString([]byte(xorEncrypted))
}

func decryptKES(base64Cipher, keyStr string) string {
	base64Decrypted, _ := base64.StdEncoding.DecodeString(base64Cipher)
	order := 0

	for _, char := range keyStr {
		order += int(char)
	}
	order %= 2

	var decrypted string

	if order == 0 {
		decodedXor := xorDecrypt(string(base64Decrypted), keyStr)
		decodedVigenere := vigenereDecrypt(decodedXor, keyStr)
		decrypted = decryptRailFence(decodedVigenere, len(keyStr))
	} else {
		decodedXor := xorDecrypt(string(base64Decrypted), keyStr)
		decodedVigenere := vigenereDecrypt(decodedXor, keyStr)
		decrypted = decryptRailFence(decodedVigenere, len(keyStr))
	}

	return decrypted
}

func main() {
	encryptionKey := "KEY321"
	plaintext := "Hello, World! KES"

	fmt.Println("Original Data:", plaintext)

	fmt.Println("XOR")
	encryptedData := xorEncrypt(plaintext, encryptionKey)
	fmt.Println("Encrypted Data:", encryptedData)
	decryptedData := xorDecrypt(encryptedData, encryptionKey)
	fmt.Println("Decrypted Data:", decryptedData)

	fmt.Println("VIGENERE")
	encryptedData = vigenereEncrypt(plaintext, encryptionKey)
	fmt.Println("Encrypted Data:", encryptedData)
	decryptedData = vigenereDecrypt(encryptedData, encryptionKey)
	fmt.Println("Decrypted Data:", decryptedData)

	fmt.Println("RAILFENCE")
	encryptedData = encryptRailFence(plaintext, len(encryptionKey))
	fmt.Println("Encrypted Data:", encryptedData)
	decryptedData = decryptRailFence(encryptedData, len(encryptionKey))
	fmt.Println("Decrypted Data:", decryptedData)

	fmt.Println("KES")
	encryptedData = encryptKES(plaintext, encryptionKey)
	fmt.Println("Encrypted Data:", encryptedData)
	decryptedData = decryptKES(encryptedData, encryptionKey)
	fmt.Println("Decrypted Data:", decryptedData)
}
