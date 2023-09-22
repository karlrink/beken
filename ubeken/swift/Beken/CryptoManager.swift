//
//  CryptoManager.swift
//  beken
//
//  Created by Karl Rink on 9/15/23.
//


import SwiftUI

import CryptoKit

class CryptoManager {
    
    
    private let symmetricKeyStr: String
    
    init(symmetricKeyStr: String) {
        self.symmetricKeyStr = symmetricKeyStr
    }
    
    func encryptXOR(plaintext: String) throws -> String {
        let xorEncrypted = xorEncrypt(plaintext: plaintext, key: symmetricKeyStr)
        return xorEncrypted
    }


    func encryptAES(plaintext: String) throws -> String {
        if let encrypted = encryptAESString(plaintext, key: symmetricKeyStr) {
            return encrypted.base64EncodedString()
        } else {
            throw EncryptionError.encryptionFailed
        }
    }

    func decryptAES(encryptedString: String) throws -> String {
        // Decode the Base64-encoded encrypted string into Data
        guard let encryptedData = Data(base64Encoded: encryptedString) else {
            throw DecryptionError.invalidBase64
        }
        
        // Decrypt the data using your decryptAESData function (assuming you have this function)
        let Decrypted = decryptAESData(encryptedData, key: symmetricKeyStr)!
        
        return Decrypted
    }

    
    
    enum CryptoError: Error {
        case decryptionFailed
    }
    
    enum DecryptionError: Error {
        case invalidBase64
        case invalidDecryptedData
    }
    
    enum EncryptionError: Error {
        case encryptionFailed
    }

    
}
