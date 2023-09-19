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
        let kesEncrypted = try encryptKES(plainText: plaintext, symmetricKey: symmetricKey)
        return kesEncrypted
    }

    func decrypt(encryptedString: String) throws -> String {
        let kesDecrypted = try decryptKES(base64Cipher: encryptedString, symmetricKey: symmetricKey)
        return kesDecrypted
    }
    
    
    enum CryptoError: Error {
        case decryptionFailed
    }
    
}
