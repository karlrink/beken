package us.rink.beken

import android.util.Base64
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

object AESUtils {
    private const val AES_ALGORITHM = "AES"
    //private const val AES_TRANSFORMATION = "AES/CBC/PKCS5Padding"
    private const val AES_TRANSFORMATION = "AES/CBC/PKCS7Padding"

    // Use a fixed IV (all zero bytes)
    private val fixedIV = ByteArray(16) // Assuming a 16-byte IV for AES/CBC


    fun generateAESKey(): SecretKey {
        val keygen = KeyGenerator.getInstance(AES_ALGORITHM)
        //keygen.init(256)
        keygen.init(128)
        return keygen.generateKey()
    }

    fun stringToSecretKey(userKey: String): SecretKey {
        // Convert the userKey string to a byte array
        val keyBytes = userKey.toByteArray()

        // Ensure that the keyBytes length is appropriate for AES (e.g., 16, 24, or 32 bytes)
        // You can adjust this logic according to your key format requirements
        if (keyBytes.size != 16 && keyBytes.size != 24 && keyBytes.size != 32) {
            throw IllegalArgumentException("Invalid key size. Key size must be 16, 24, or 32 bytes.")
        }

        // Create a SecretKeySpec from the keyBytes
        return SecretKeySpec(keyBytes, AES_ALGORITHM)
    }

    fun encrypt(text: String, userKey: String): String {
        // Convert the userKey string to a SecretKey
        val secretKey = stringToSecretKey(userKey)

        // Create an IvParameterSpec with a fixed IV
        val ivSpec = IvParameterSpec(fixedIV)


        // Perform encryption
        val cipher = Cipher.getInstance(AES_TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec)
        val encryptedBytes = cipher.doFinal(text.toByteArray())
        return Base64.encodeToString(encryptedBytes, Base64.DEFAULT)
        //return Base64.encodeToString(encryptedBytes, Base64.NO_WRAP)
    }

    fun decrypt(encryptedText: String, userKey: String): String {
        // Convert the userKey string to a SecretKey
        val secretKey = stringToSecretKey(userKey)

        // Perform decryption
        val cipher = Cipher.getInstance(AES_TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, secretKey)
        val decryptedBytes = cipher.doFinal(Base64.decode(encryptedText, Base64.DEFAULT))
        return String(decryptedBytes)
    }

}
