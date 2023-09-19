#!/bin/bash

xorEncrypt() {
    plaintext="$1"
    keyStr="$2"
    encryptedData=""
    keyLength=${#keyStr}

    for ((i=0; i<${#plaintext}; i++)); do
        byte="${plaintext:$i:1}"
        keyByte="${keyStr:$((i % keyLength)):1}"
        encryptedByte=$(( (16#$(printf "%02x" "'$byte")) ^ (16#$(printf "%02x" "'$keyByte")) ))
        encryptedData+=$(printf "%02x" $encryptedByte)
    done

    echo -n "$encryptedData" | xxd -r -p | base64
}

xorDecrypt() {
    base64Cipher="$1"
    keyStr="$2"
    cipherBytes=$(echo -n "$base64Cipher" | base64 -d | xxd -p -c 100000)
    keyLength=${#keyStr}
    decryptedData=""

    for ((i=0; i<${#cipherBytes}; i+=2)); do
        hexByte="${cipherBytes:$i:2}"
        keyByte="${keyStr:$((i / 2 % keyLength)):1}"
        decryptedByte=$(( (16#$hexByte) ^ (16#$(printf "%02x" "'$keyByte")) ))
        decryptedData+=$(printf "\\x$(printf "%02x" $decryptedByte)")
    done

    echo -n -e "$decryptedData"
}

# Rest of the script remains the same

encryptionKey="KEY321"
plaintext="Hello, World! KES"

echo "Original Data: $plaintext"

echo "XOR"
encryptedData=$(xorEncrypt "$plaintext" "$encryptionKey")
echo "Encrypted Data: $encryptedData"
decryptedData=$(xorDecrypt "$encryptedData" "$encryptionKey")
echo "Decrypted Data: $decryptedData"


