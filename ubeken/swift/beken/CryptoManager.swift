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
        let xorEncrypted = xorEncrypt(plainText: plaintext, keyStr: symmetricKeyStr)
        return xorEncrypted
    }

    func decrypt(encryptedString: String) throws -> String {
        let xorDecrypted = xorDecrypt(base64Cipher: encryptedString, keyStr: symmetricKeyStr)
        return xorDecrypted
    }
    
    
    enum CryptoError: Error {
        case decryptionFailed
    }
    
}
