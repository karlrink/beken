#!/bin/bash


vigenereEncrypt() {
    plaintext="$1"
    keyStr="$2"
    encryptedData=""

    for ((i=0; i<${#plaintext}; i++)); do
        plaintextByte="${plaintext:$i:1}"
        keyByte="${keyStr:$((i % ${#keyStr})):1}"
        encryptedByte=$(( (16#$(printf "%02x" "'$plaintextByte")) + (16#$(printf "%02x" "'$keyByte")) ))
        encryptedData+=$(printf "%02x" $encryptedByte)
    done

    echo -n "$encryptedData"
}

vigenereDecrypt() {
    hexCipher="$1"
    keyStr="$2"
    decryptedData=""

    for ((i=0; i<${#hexCipher}; i+=2)); do
        hexByte="${hexCipher:$i:2}"
        keyByte="${keyStr:$((i / 2 % ${#keyStr})):1}"
        decryptedByte=$(( (16#$hexByte) - (16#$(printf "%02x" "'$keyByte")) ))
        decryptedData+=$(printf "\\x$(printf "%02x" $decryptedByte)")
    done

    echo -n -e "$decryptedData"
}

# Rest of the script remains the same

encryptionKey="KEY321"
plaintext="Hello, World! KES"

echo "Original Data: $plaintext"

echo "VIGENERE"
encryptedData=$(vigenereEncrypt "$plaintext" "$encryptionKey")
echo "Encrypted Data: $encryptedData"
decryptedData=$(vigenereDecrypt "$encryptedData" "$encryptionKey")
echo "Decrypted Data: $decryptedData"


