package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"fmt"
)

// EncryptionKey is the key used for encryption.
const EncryptionKey = "KEY"

func xorEncryptDecrypt(data, xorKey byte) []byte {
	encryptedData := make([]byte, len(data))
	for i, b := range data {
		encryptedData[i] = b ^ xorKey
	}
	return encryptedData
}

func vigenereEncryptDecrypt(data []byte, vigenereKey string, encrypt bool) []byte {
	encryptedData := make([]byte, len(data))
	keyLength := len(vigenereKey)

	for i, b := range data {
		keyByte := vigenereKey[i%keyLength]
		if encrypt {
			encryptedData[i] = (b + keyByte) % 256
		} else {
			encryptedData[i] = (b - keyByte) % 256
		}
	}
	return encryptedData
}

func transpose(data []byte, transpositionKey []int, encrypt bool) []byte {
	transposedData := make([]byte, len(data))

	for i, pos := range transpositionKey {
		if encrypt {
			transposedData[i] = data[pos-1]
		} else {
			transposedData[pos-1] = data[i]
		}
	}
	return transposedData
}

func signData(data []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
	hashed := sha256.Sum256(data)
	signature, err := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, hashed[:], nil)
	if err != nil {
		return nil, err
	}
	return signature, nil
}

func verifySignature(data, signature []byte, publicKey *rsa.PublicKey) error {
	hashed := sha256.Sum256(data)
	return rsa.VerifyPSS(publicKey, crypto.SHA256, hashed[:], signature, nil)
}

func customEncrypt(data []byte, encryptionKey string, privateKey *rsa.PrivateKey) ([]byte, []byte, error) {
	// Determine the order of encryption based on the encryption key
	order := 0
	for _, char := range encryptionKey {
		order += int(char)
	}
	order %= 3 // 3 encryption steps

	var encryptedData []byte

	if order == 0 {
		// XOR -> Vigenère -> Transposition
		encryptedData = xorEncryptDecrypt(data, encryptionKey[0])
		encryptedData = vigenereEncryptDecrypt(encryptedData, encryptionKey, true)
		encryptedData = transpose(encryptedData, []int{2, 4, 1, 3, 5}, true)
	} else if order == 1 {
		// Vigenère -> Transposition -> XOR
		encryptedData = vigenereEncryptDecrypt(data, encryptionKey, true)
		encryptedData = transpose(encryptedData, []int{2, 4, 1, 3, 5}, true)
		encryptedData = xorEncryptDecrypt(encryptedData, encryptionKey[0])
	} else {
		// Transposition -> XOR -> Vigenère
		encryptedData = transpose(data, []int{2, 4, 1, 3, 5}, true)
		encryptedData = xorEncryptDecrypt(encryptedData, encryptionKey[0])
		encryptedData = vigenereEncryptDecrypt(encryptedData, encryptionKey, true)
	}

	// Sign the encrypted data
	signature, err := signData(encryptedData, privateKey)
	if err != nil {
		return nil, nil, err
	}

	return encryptedData, signature, nil
}

func customDecrypt(data []byte, encryptionKey string, publicKey *rsa.PublicKey) ([]byte, error) {
	// Split the data into the encrypted portion and the signature
	signatureLength := 256 // Adjust this based on your key size
	dataLength := len(data) - signatureLength

	if dataLength <= 0 {
		return nil, errors.New("invalid data length")
	}

	encryptedData := data[:dataLength]
	signature := data[dataLength:]

	// Verify the signature
	if err := verifySignature(encryptedData, signature, publicKey); err != nil {
		return nil, err
	}

	// Determine the order of decryption based on the encryption key
	order := 0
	for _, char := range encryptionKey {
		order += int(char)
	}
	order %= 3 // 3 encryption steps

	var decryptedData []byte

	if order == 0 {
		// Transposition -> XOR -> Vigenère
		decryptedData = transpose(encryptedData, []int{2, 4, 1, 3, 5}, false)
		decryptedData = xorEncryptDecrypt(decryptedData, encryptionKey[0])
		decryptedData = vigenereEncryptDecrypt(decryptedData, encryptionKey, false)
	} else if order == 1 {
		// XOR -> Vigenère -> Transposition
		decryptedData = xorEncryptDecrypt(encryptedData, encryptionKey[0])
		decryptedData = vigenereEncryptDecrypt(decryptedData, encryptionKey, false)
		decryptedData = transpose(decryptedData, []int{2, 4, 1, 3, 5}, false)
	} else {
		// Vigenère -> Transposition -> XOR
		decryptedData = vigenereEncryptDecrypt(encryptedData, encryptionKey, false)
		decryptedData = transpose(decryptedData, []int{2, 4, 1, 3, 5}, false)
		decryptedData = xorEncryptDecrypt(decryptedData, encryptionKey[0])
	}

	return decryptedData, nil
}

func main() {
	// Sample data to encrypt
	plaintext := []byte("Hello, World!")

	// Generate an RSA key pair for signing and verification
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Println("Error generating private key:", err)
		return
	}
	publicKey := &privateKey.PublicKey

	// Encrypt the data
	encryptedData, signature, err := customEncrypt(plaintext, EncryptionKey, privateKey)
	if err != nil {
		fmt.Println("Error encrypting data:", err)
		return
	}

	fmt.Println("Original Data:", string(plaintext))
	fmt.Println("Encrypted Data:", encryptedData)
	fmt.Println("Signature:", signature)

	// Decrypt the data
	decryptedData, err := customDecrypt(append(encryptedData, signature...), EncryptionKey, publicKey)
	if err != nil {
		fmt.Println("Error decrypting data:", err)
		return
	}

	fmt.Println("Decrypted Data:", string(decryptedData))
}
