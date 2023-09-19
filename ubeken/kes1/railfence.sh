#!/bin/bash

encryptRailFence() {
    plaintext="$1"
    numRails="$2"
    encodedPlainText=$(echo -n "$plaintext" | base64)

    rails=()
    for ((i=0; i<numRails; i++)); do
        rails+=("")
    done

    railIndex=0
    direction=1

    for ((i=0; i<${#encodedPlainText}; i++)); do
        char="${encodedPlainText:$i:1}"
        rails[railIndex]+="$char"

        if [ $railIndex -eq 0 ]; then
            direction=1
        elif [ $railIndex -eq $((numRails - 1)) ]; then
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
        rails[railIndex]+="."

        if [ $railIndex -eq 0 ]; then
            direction=1
        elif [ $railIndex -eq $((numRows - 1)) ]; then
            direction=-1
        fi

        railIndex=$((railIndex + direction))
    done

    railIndex=0
    direction=1

    for ((i = 0; i < ${#cipherText}; i++)); do
        char="${cipherText:$i:1}"
        rails[railIndex]="${char}${rails[railIndex]:1}"

        if [ $railIndex -eq 0 ]; then
            direction=1
        elif [ $railIndex -eq $((numRows - 1)) ]; then
            direction=-1
        fi

        railIndex=$((railIndex + direction))
    done

    plainText=""
    railIndex=0
    direction=1

    for ((i = 0; i < railLength; i++)); do
        if [ -n "${rails[railIndex]}" ]; then
            plainText+="${rails[railIndex]:0:1}"
            rails[railIndex]=${rails[railIndex]:1}
        fi

        if [ $railIndex -eq 0 ]; then
            direction=1
        elif [ $railIndex -eq $((numRows - 1)) ]; then
            direction=-1
        fi

        railIndex=$((railIndex + direction))
    done

    echo -n "$plainText" | tr -d '.'
}






encryptionKey="KEY321"
plaintext="Hello, World! KES"

echo "Original Data: $plaintext"

echo "RAILFENCE"
encryptedData=$(encryptRailFence "$plaintext" "${#encryptionKey}")
echo "Encrypted Data: $encryptedData"
decryptedData=$(decryptRailFence "$encryptedData" "${#encryptionKey}")
echo "Decrypted Data: $decryptedData"


