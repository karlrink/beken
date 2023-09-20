
import Foundation
import CommonCrypto

func encryptAES128(_ data: Data, key: Data, iv: Data) -> Data? {
    var encryptedData = Data(count: data.count + kCCBlockSizeAES128)
    var encryptedDataLength: Int = 0

    let status = key.withUnsafeBytes { keyBytes in
        iv.withUnsafeBytes { ivBytes in
            data.withUnsafeBytes { dataBytes in
                CCCrypt(
                    CCOperation(kCCEncrypt),
                    CCAlgorithm(kCCAlgorithmAES),
                    CCOptions(kCCOptionPKCS7Padding),
                    keyBytes.baseAddress, key.count,
                    ivBytes.baseAddress,
                    dataBytes.baseAddress, data.count,
                    encryptedData.withUnsafeMutableBytes { $0.baseAddress }, encryptedData.count,
                    &encryptedDataLength
                )
            }
        }
    }

    if status == kCCSuccess {
        encryptedData.count = encryptedDataLength
        return encryptedData
    } else {
        return nil
    }
}

func decryptAES128(_ data: Data, key: Data, iv: Data) -> Data? {
    var decryptedData = Data(count: data.count)
    var decryptedDataLength: Int = 0

    let status = key.withUnsafeBytes { keyBytes in
        iv.withUnsafeBytes { ivBytes in
            data.withUnsafeBytes { dataBytes in
                CCCrypt(
                    CCOperation(kCCDecrypt),
                    CCAlgorithm(kCCAlgorithmAES),
                    CCOptions(kCCOptionPKCS7Padding),
                    keyBytes.baseAddress, key.count,
                    ivBytes.baseAddress,
                    dataBytes.baseAddress, data.count,
                    decryptedData.withUnsafeMutableBytes { $0.baseAddress }, decryptedData.count,
                    &decryptedDataLength
                )
            }
        }
    }

    if status == kCCSuccess {
        decryptedData.count = decryptedDataLength
        return decryptedData
    } else {
        return nil
    }
}

func encryptAESString(_ input: String, key: String) -> Data? {
    guard let data = input.data(using: .utf8), let keyData = key.data(using: .utf8) else {
        return nil
    }

    let ivData = Data(count: kCCBlockSizeAES128)

    return encryptAES128(data, key: keyData, iv: ivData)
}

func decryptAESData(_ data: Data, key: String) -> String? {
    guard let keyData = key.data(using: .utf8) else {
        return nil
    }

    let ivData = Data(count: kCCBlockSizeAES128)

    guard let decryptedData = decryptAES128(data, key: keyData, iv: ivData),
          let decryptedString = String(data: decryptedData, encoding: .utf8) else {
        return nil
    }

    return decryptedString
}

let plaintext = "AES128 Symmetric Encryption key length is 128 bits (16 bytes)"

if let encryptedData = encryptAESString(plaintext, key: "1234567890123456") {
    print("Encrypted: \(encryptedData.base64EncodedString())")

    if let decryptedString = decryptAESData(encryptedData, key: "1234567890123456") {
        print("Decrypted: \(decryptedString)")
    } else {
        print("Decryption failed.")
    }
} else {
    print("Encryption failed.")
}


