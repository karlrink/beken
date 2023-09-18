//
//  CryptoManager.swift
//  beken
//
//  Created by Karl Rink on 9/15/23.
//


import SwiftUI

import CryptoKit

class CryptoManager {
    
    private let symmetricKey: SymmetricKey

    init(symmetricKeyStr: String) {
        // Convert the provided key string to Data
        guard let keyData = Data(base64Encoded: symmetricKeyStr) else {
            fatalError("Invalid symmetric key string")
        }
        
        // Create a SymmetricKey from the key data
        self.symmetricKey = SymmetricKey(data: keyData)
    }

    func encrypt(plaintext: String) throws -> String {
        let plaintextData = plaintext.data(using: .utf8)!
        let nonce = AES.GCM.Nonce()
        let sealedBox = try AES.GCM.seal(plaintextData, using: symmetricKey, nonce: nonce)

        // Convert nonce to Data and then to a base64-encoded string
        let nonceData = Data(nonce)
        let nonceBase64 = nonceData.base64EncodedString()

        // Convert ciphertext and tag to base64-encoded strings
        let cipherBase64 = sealedBox.ciphertext.base64EncodedString()
        let tagBase64 = sealedBox.tag.base64EncodedString()

        // Combine all base64-encoded values into a single string with spaces
        let encryptedString = [cipherBase64, nonceBase64, tagBase64].joined(separator: " ")

        return encryptedString
    }

    func decrypt(encryptedString: String) throws -> String {
        // Split the encryptedString into base64-encoded values
        let components = encryptedString.components(separatedBy: " ")

        // Ensure we have exactly 3 components
        guard components.count == 3 else {
            throw CryptoError.decryptionFailed
        }

        // Unwrap the components
        let cipherBase64 = components[0]
        let nonceBase64 = components[1]
        let tagBase64 = components[2]

        // Convert base64 strings to Data
        guard let cipherData = Data(base64Encoded: cipherBase64),
              let nonceData = Data(base64Encoded: nonceBase64),
              let tagData = Data(base64Encoded: tagBase64) else {
            throw CryptoError.decryptionFailed
        }

        // Convert nonce Data back to AES.GCM.Nonce
        let nonceBytes = Array(nonceData)
        guard let nonce = try? AES.GCM.Nonce(data: nonceBytes) else {
            throw CryptoError.decryptionFailed
        }

        let sealedBox = try AES.GCM.SealedBox(nonce: nonce, ciphertext: cipherData, tag: tagData)
        let decryptedData = try AES.GCM.open(sealedBox, using: symmetricKey)

        guard let plaintext = String(data: decryptedData, encoding: .utf8) else {
            throw CryptoError.decryptionFailed
        }

        return plaintext
    }
}

enum CryptoError: Error {
    case decryptionFailed
}
