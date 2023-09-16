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
        
        guard let keyData = keyStr.data(using: .utf8) else {
            throw CryptoError.invalidKey
        }
        
        let nonce = try! AES.GCM.Nonce(data: generateNonce())
        
        do {
           
            let messageData = message.data(using: .utf8)!
            let sealedBox = try AES.GCM.seal(messageData, using: SymmetricKey(data: keyData), nonce: nonce)
            
            let base64Cipher = sealedBox.ciphertext.base64EncodedString()
            let base64Tag = sealedBox.tag.base64EncodedString() // Include the tag
            
            let base64Nonce = nonce.withUnsafeBytes { Data($0) }.base64EncodedString()
            
            return "\(base64Cipher) \(base64Nonce) \(base64Tag)" // Include the tag in the returned string
            
        } catch {
            throw CryptoError.encryptionError(error)
        }
    }
    
    static func decryptMessage(encryptedMessage: String, keyStr: String) throws -> String {
        
        guard let keyData = keyStr.data(using: .utf8) else {
            throw CryptoError.invalidKey
        }
                
        let components = encryptedMessage.components(separatedBy: " ")
        
        if components.count >= 3 {
            let base64Cipher = components[0]
            let base64Nonce = components[1]
            let base64Tag = components[2] // Retrieve the tag
            
            guard let cipherData = Data(base64Encoded: base64Cipher),
                  let nonceData = Data(base64Encoded: base64Nonce),
                  let tagData = Data(base64Encoded: base64Tag) else {
                throw CryptoError.invalidMessage
            }

            let nonce = try! AES.GCM.Nonce(data: nonceData)
            let sealedBox = try AES.GCM.SealedBox(nonce: nonce, ciphertext: cipherData, tag: tagData) // Include the tag

            do {
                //print("This is my key: ", keyData)
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

    static func generateNonce() -> Data {
        var nonce = Data(count: 12)
        _ = nonce.withUnsafeMutableBytes { mutableBytes in
            SecRandomCopyBytes(kSecRandomDefault, 12, mutableBytes.baseAddress!)
        }
        return nonce
    }
}

enum CryptoError: Error {
    case invalidKey
    case encryptionError(Error)
    case decryptionError
    case invalidMessage
}
