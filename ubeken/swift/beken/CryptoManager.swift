//
//  CryptoManager.swift
//  beken
//
//  Created by Karl Rink on 9/15/23.
//

import Foundation

class CryptoManager {
    private let sharedSecretKey: UInt8
    
    init(sharedSecretKey: UInt8) {
        self.sharedSecretKey = sharedSecretKey
    }
    
    func encrypt(plaintext: Data) -> Data {
        let inputBytes = [UInt8](plaintext)
        let encryptedBytes = encrypt(input: inputBytes, key: sharedSecretKey)
        return Data(encryptedBytes)
    }
    
    func decrypt(encryptedData: Data) -> Data {
        let encryptedBytes = [UInt8](encryptedData)
        let decryptedBytes = decrypt(encrypted: encryptedBytes, key: sharedSecretKey)
        return Data(decryptedBytes)
    }
    
    private func encrypt(input: [UInt8], key: UInt8) -> [UInt8] {
        return input.map { $0 ^ key }
    }
    
    private func decrypt(encrypted: [UInt8], key: UInt8) -> [UInt8] {
        return encrypt(input: encrypted, key: key)
    }
}
