//
//  CryptoManager.swift
//  beken
//
//  Created by Karl Rink on 9/15/23.
//

import Foundation
import CryptoKit

struct CryptoManager {
    static func encryptMessage(message: String, keyStr: String) throws -> String {
        guard let keyData = Data(base64Encoded: keyStr) else {
            throw CryptoError.invalidKey
        }
        
        let nonce = AES.GCM.Nonce()
        
        do {
            let messageData = "\(message) ".data(using: .utf8)! // Convert plaintext to Data
            let sealedBox = try AES.GCM.seal(messageData, using: SymmetricKey(data: keyData), nonce: nonce)
            
            let base64Cipher = sealedBox.ciphertext.withUnsafeBytes { Data($0) }.base64EncodedString()
            let base64Nonce = nonce.withUnsafeBytes { Data($0) }.base64EncodedString()
            
            return "\(base64Cipher) \(base64Nonce)"
        } catch {
            throw CryptoError.encryptionError(error)
        }
    }
    
    static func decryptMessage(encryptedMessage: String, keyStr: String) throws -> String {
        guard let keyData = Data(base64Encoded: keyStr) else {
            throw CryptoError.invalidKey
        }
        
        let components = encryptedMessage.components(separatedBy: " ")
        
        if components.count >= 3 {
            let base64Cipher = components[0]
            let base64Nonce = components[1]
            let base64Tag = components[2]

            guard let cipherData = Data(base64Encoded: base64Cipher),
                  let nonceData = Data(base64Encoded: base64Nonce),
                  let tagData = Data(base64Encoded: base64Tag) else {
                throw CryptoError.invalidMessage
            }

            let nonce = try AES.GCM.Nonce(data: nonceData)
            let sealedBox = try AES.GCM.SealedBox(nonce: nonce, ciphertext: cipherData, tag: tagData)

            do {
                let decryptedData = try AES.GCM.open(sealedBox, using: SymmetricKey(data: keyData))
                
                if let message = String(data: decryptedData, encoding: .utf8) {
                    return message
                } else {
                    throw CryptoError.decryptionError
                }
            } catch {
                throw CryptoError.decryptionError
            }
        } else {
            throw CryptoError.invalidMessage
        }
    }
}

enum CryptoError: Error {
    case invalidKey
    case encryptionError(Error)
    case decryptionError
    case invalidMessage
}
