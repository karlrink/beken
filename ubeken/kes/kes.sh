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


encryptRailFence() {
    plaintext="$1"
    numRails="$2"
    encodedPlainText=$(echo -n "$plaintext" | base64)
    rails=()
    railIndex=0
    direction=1

    for ((i=0; i<${#encodedPlainText}; i++)); do
        char="${encodedPlainText:$i:1}"
        rails[$railIndex]+="$char"

        if [ "$railIndex" -eq 0 ]; then
            direction=1
        elif [ "$railIndex" -eq "$((numRails-1))" ]; then
            direction=-1
        fi

        railIndex=$((railIndex + direction))
    done

    cipherText=""
    for rail in "${rails[@]}"; do
        cipherText+="$rail"
    done

    echo -n "$cipherText" | base64
}

decryptRailFence() {
    base64Cipher="$1"
    numRails="$2"
    cipherText=$(echo -n "$base64Cipher" | base64 -d)
    railLength=$(( (${#cipherText} + numRails - 1) / numRails ))
    numRows=$(( (railLength - 1) * 2 + 1 ))

    rails=()
    for ((i = 0; i < numRows; i++)); do
        rails+=("")
    done

    railIndex=0
    direction=1

    for ((i = 0; i < ${#cipherText}; i++)); do
        char="${cipherText:$i:1}"
        rails[railIndex]+="$char"

        if [ $railIndex -eq 0 ]; then
            direction=1
        elif [ $railIndex -eq $((numRows - 1)) ]; then
            direction=-1
        fi

        railIndex=$((railIndex + direction))
    done

    plainText=""
    for ((i = 0; i < numRows; i++)); do
        plainText+="${rails[i]}"
    done

    echo -n "$plainText" | base64 -d
}


encryptKES() {
    plainText="$1"
    keyStr="$2"
    order=0

    for ((i=0; i<${#keyStr}; i++)); do
        char="${keyStr:$i:1}"
        order=$((order + $(printf "%d" "'$char")))
    done

    order=$((order % 2))
    railFenceEncrypted=$(encryptRailFence "$plainText" "${#keyStr}")

    if [ "$order" -eq 0 ]; then
        xorEncrypted=$(xorEncrypt "$railFenceEncrypted" "$keyStr")
        encrypted=$(vigenereEncrypt "$xorEncrypted" "$keyStr")
        echo -n "$encrypted" | base64
    else
        vigenereEncrypted=$(vigenereEncrypt "$railFenceEncrypted" "$keyStr")
        xorEncrypted=$(xorEncrypt "$vigenereEncrypted" "$keyStr")
        echo -n "$xorEncrypted" | base64
    fi
}

decryptKES() {
    base64Cipher="$1"
    keyStr="$2"
    base64Decrypted=$(echo -n "$base64Cipher" | base64 -d)
    order=0

    for ((i=0; i<${#keyStr}; i++)); do
        char="${keyStr:$i:1}"
        order=$((order + $(printf "%d" "'$char")))
    done

    order=$((order % 2))
    decodedXor=$(xorDecrypt "$base64Decrypted" "$keyStr")
    decodedVigenere=$(vigenereDecrypt "$decodedXor" "$keyStr")

    if [ "$order" -eq 0 ]; then
        decryptRailFence "$decodedVigenere" "${#keyStr}"
    else
        decryptRailFence "$decodedVigenere" "${#keyStr}"
    fi
}

encryptionKey="KEY321"
plaintext="Hello, World! KES"

echo "Original Data: $plaintext"

echo "XOR"
encryptedData=$(xorEncrypt "$plaintext" "$encryptionKey")
echo "Encrypted Data: $encryptedData"
decryptedData=$(xorDecrypt "$encryptedData" "$encryptionKey")
echo "Decrypted Data: $decryptedData"

echo "VIGENERE"
encryptedData=$(vigenereEncrypt "$plaintext" "$encryptionKey")
echo "Encrypted Data: $encryptedData"
decryptedData=$(vigenereDecrypt "$encryptedData" "$encryptionKey")
echo "Decrypted Data: $decryptedData"

echo "RAILFENCE"
encryptedData=$(encryptRailFence "$plaintext" "${#encryptionKey}")
echo "Encrypted Data: $encryptedData"
decryptedData=$(decryptRailFence "$encryptedData" "${#encryptionKey}")
echo "Decrypted Data: $decryptedData"

echo "KES"
encryptedData=$(encryptKES "$plaintext" "$encryptionKey")
echo "Encrypted Data: $encryptedData"
decryptedData=$(decryptKES "$encryptedData" "$encryptionKey")
echo "Decrypted Data: $decryptedData"


