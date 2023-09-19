package kes

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

func XorEncrypt(plainText, keyStr string) string {
	plaintextBytes := []byte(plainText)
	keyBytes := []byte(keyStr)
	encryptedData := make([]byte, len(plaintextBytes))

	for i, byte := range plaintextBytes {
		keyByte := keyBytes[i%len(keyBytes)]
		encryptedData[i] = byte ^ keyByte
	}

	return base64.StdEncoding.EncodeToString(encryptedData)
}

func XorDecrypt(base64Cipher, keyStr string) string {
	cipherBytes, _ := base64.StdEncoding.DecodeString(base64Cipher)
	keyBytes := []byte(keyStr)
	decryptedData := make([]byte, len(cipherBytes))

	for i, byte := range cipherBytes {
		keyByte := keyBytes[i%len(keyBytes)]
		decryptedData[i] = byte ^ keyByte
	}

	return string(decryptedData)
}

func VigenereEncrypt(plainText, keyStr string) string {
	plaintextBytes := []byte(plainText)
	keyBytes := []byte(keyStr)
	encryptedData := make([]byte, len(plaintextBytes))

	for i, byte := range plaintextBytes {
		keyByte := keyBytes[i%len(keyBytes)]
		encryptedData[i] = byte + keyByte
	}

	return fmt.Sprintf("%x", encryptedData)
}

func VigenereDecrypt(hexCipher, keyStr string) string {
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

func EncryptRailFence(plainText string, numRails int) string {
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

func DecryptRailFence(base64Cipher string, numRails int) string {
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

func EncryptKES(plainText, keyStr string) string {
	order := 0

	for _, char := range keyStr {
		order += int(char)
	}
	order %= 2

	railFenceEncrypted := EncryptRailFence(plainText, len(keyStr))

	if order == 0 {
		xorEncrypted := XorEncrypt(railFenceEncrypted, keyStr)
		encrypted := VigenereEncrypt(xorEncrypted, keyStr)
		return base64.StdEncoding.EncodeToString([]byte(encrypted))
	}

	vigenereEncrypted := VigenereEncrypt(railFenceEncrypted, keyStr)
	xorEncrypted := XorEncrypt(vigenereEncrypted, keyStr)

	return base64.StdEncoding.EncodeToString([]byte(xorEncrypted))
}

func DecryptKES(base64Cipher, keyStr string) string {
	base64Decrypted, _ := base64.StdEncoding.DecodeString(base64Cipher)
	order := 0

	for _, char := range keyStr {
		order += int(char)
	}
	order %= 2

	var decrypted string

	if order == 0 {
		decodedXor := XorDecrypt(string(base64Decrypted), keyStr)
		decodedVigenere := VigenereDecrypt(decodedXor, keyStr)
		decrypted = DecryptRailFence(decodedVigenere, len(keyStr))
	} else {
		decodedXor := XorDecrypt(string(base64Decrypted), keyStr)
		decodedVigenere := VigenereDecrypt(decodedXor, keyStr)
		decrypted = DecryptRailFence(decodedVigenere, len(keyStr))
	}

	return decrypted
}
