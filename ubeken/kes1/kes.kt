
import java.util.*

fun xorEncrypt(plainText: String, keyStr: String): String {
    val plaintextBytes = plainText.toByteArray()
    val keyBytes = keyStr.toByteArray()
    val encryptedData = ByteArray(plaintextBytes.size)

    for (i in plaintextBytes.indices) {
        val keyByte = keyBytes[i % keyBytes.size]
        encryptedData[i] = (plaintextBytes[i].toInt() xor keyByte.toInt()).toByte()
    }

    return Base64.getEncoder().encodeToString(encryptedData)
}

fun xorDecrypt(base64Cipher: String, keyStr: String): String {
    val cipherBytes = Base64.getDecoder().decode(base64Cipher)
    val keyBytes = keyStr.toByteArray()
    val decryptedData = ByteArray(cipherBytes.size)

    for (i in cipherBytes.indices) {
        val keyByte = keyBytes[i % keyBytes.size]
        decryptedData[i] = (cipherBytes[i].toInt() xor keyByte.toInt()).toByte()
    }

    return String(decryptedData)
}

fun vigenereEncrypt(plainText: String, keyStr: String): String {
    val plaintextBytes = plainText.toByteArray()
    val keyBytes = keyStr.toByteArray()
    val encryptedData = ByteArray(plaintextBytes.size)

    for (i in plaintextBytes.indices) {
        val keyByte = keyBytes[i % keyBytes.size]
        encryptedData[i] = (plaintextBytes[i] + keyByte).toByte()
    }

    return encryptedData.joinToString("") { String.format("%02x", it) }
}

fun vigenereDecrypt(hexCipher: String, keyStr: String): String {
    val hexCipherBytes = hexCipher.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    val keyBytes = keyStr.toByteArray()
    val decryptedData = ByteArray(hexCipherBytes.size)

    for (i in hexCipherBytes.indices) {
        val keyByte = keyBytes[i % keyBytes.size]
        val decryptedByte = ((hexCipherBytes[i].toInt() - keyByte.toInt() + 256) % 256).toByte()
        decryptedData[i] = decryptedByte
    }

    return String(decryptedData)
}

fun encryptRailFence(plainText: String, numRails: Int): String {
    val encodedPlainText = Base64.getEncoder().encodeToString(plainText.toByteArray())
    val rails = Array(numRails) { StringBuilder() }
    var railIndex = 0
    var direction = 1

    for (char in encodedPlainText) {
        rails[railIndex].append(char)

        if (railIndex == 0) {
            direction = 1
        } else if (railIndex == numRails - 1) {
            direction = -1
        }

        railIndex += direction
    }

    val cipherText = rails.joinToString("")

    return Base64.getEncoder().encodeToString(cipherText.toByteArray())
}

fun decryptRailFence(base64Cipher: String, numRails: Int): String {
    val cipherText = String(Base64.getDecoder().decode(base64Cipher))
    val rails = Array(numRails) { CharArray(cipherText.length) }
    var railIndex = 0
    var direction = 1
    var index = 0

    for (i in cipherText.indices) {
        rails[railIndex][i] = '*'

        if (railIndex == 0) {
            direction = 1
        } else if (railIndex == numRails - 1) {
            direction = -1
        }

        railIndex += direction
    }

    for (i in 0 until numRails) {
        for (j in cipherText.indices) {
            if (rails[i][j] == '*' && index < cipherText.length) {
                rails[i][j] = cipherText[index]
                index++
            }
        }
    }

    val plainText = StringBuilder()
    railIndex = 0
    direction = 1

    for (i in cipherText.indices) {
        plainText.append(rails[railIndex][i])

        if (railIndex == 0) {
            direction = 1
        } else if (railIndex == numRails - 1) {
            direction = -1
        }

        railIndex += direction
    }

    return String(Base64.getDecoder().decode(plainText.toString()))
}

fun encryptKES(plainText: String, keyStr: String): String {
    val order = keyStr.sumOf { it.code } % 2
    val railFenceEncrypted = encryptRailFence(plainText, keyStr.length)

    return if (order == 0) {
        val xorEncrypted = xorEncrypt(railFenceEncrypted, keyStr)
        val encrypted = vigenereEncrypt(xorEncrypted, keyStr)
        Base64.getEncoder().encodeToString(encrypted.toByteArray())
    } else {
        val vigenereEncrypted = vigenereEncrypt(railFenceEncrypted, keyStr)
        val xorEncrypted = xorEncrypt(vigenereEncrypted, keyStr)
        Base64.getEncoder().encodeToString(xorEncrypted.toByteArray())
    }
}

fun decryptKES(base64Cipher: String, keyStr: String): String {
    val base64Decrypted = Base64.getDecoder().decode(base64Cipher)
    val order = keyStr.sumOf { it.code } % 2
    val decrypted: String

    decrypted = if (order == 0) {
        val decodedXor = xorDecrypt(String(base64Decrypted), keyStr)
        val decodedVigenere = vigenereDecrypt(decodedXor, keyStr)
        decryptRailFence(decodedVigenere, keyStr.length)
    } else {
        val decodedXor = xorDecrypt(String(base64Decrypted), keyStr)
        val decodedVigenere = vigenereDecrypt(decodedXor, keyStr)
        decryptRailFence(decodedVigenere, keyStr.length)
    }

    return decrypted
}

fun main() {
    val encryptionKey = "KEY321"
    val plaintext = "Hello, World! KES"

    println("Original Data: $plaintext")

    println("XOR")
    var encryptedData = xorEncrypt(plaintext, encryptionKey)
    println("Encrypted Data: $encryptedData")
    var decryptedData = xorDecrypt(encryptedData, encryptionKey)
    println("Decrypted Data: $decryptedData")

    println("VIGENERE")
    encryptedData = vigenereEncrypt(plaintext, encryptionKey)
    println("Encrypted Data: $encryptedData")
    decryptedData = vigenereDecrypt(encryptedData, encryptionKey)
    println("Decrypted Data: $decryptedData")

    println("RAILFENCE")
    encryptedData = encryptRailFence(plaintext, encryptionKey.length)
    println("Encrypted Data: $encryptedData")
    decryptedData = decryptRailFence(encryptedData, encryptionKey.length)
    println("Decrypted Data: $decryptedData")

    println("KES")
    encryptedData = encryptKES(plaintext, encryptionKey)
    println("Encrypted Data: $encryptedData")
    decryptedData = decryptKES(encryptedData, encryptionKey)
    println("Decrypted Data: $decryptedData")
}

