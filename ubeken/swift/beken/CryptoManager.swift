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


    func encrypt(plaintext: String) throws -> String {
        let Encrypted = try encryptKES(plainText: plaintext, keyStr: symmetricKeyStr)
        return Encrypted
    }

    func decrypt(encryptedString: String) throws -> String {
        let Decrypted = try decryptKES(base64Cipher: encryptedString, keyStr: symmetricKeyStr)
        return Decrypted
    }
    
    
    enum CryptoError: Error {
        case decryptionFailed
    }
    
}
