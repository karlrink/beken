//
//  NetworkManager.swift
//  beken
//
//  Created by Karl Rink on 9/20/23.
//

import Network
import CryptoKit
import Foundation

class NetworkManager2: ObservableObject {
    @Published var outputMessage: String = ""
    @Published var isDataSent: Bool = false

    private var connection: NWConnection?

    func setupUDPConnection(serverAddress: String, serverPort: String) {
        connection = NWConnection(
            host: NWEndpoint.Host(serverAddress),
            port: NWEndpoint.Port(serverPort)!, using: .udp
        )
    }

    func sendUDPData(nameStr: String, keyStr: String) {
        self.outputMessage = "fail"
         
         let trimmedKeyStr = keyStr.trimmingCharacters(in: .whitespacesAndNewlines)
         print(trimmedKeyStr)
       
         let cryptoManager = CryptoManager(symmetricKeyStr: trimmedKeyStr)

        do {
            let dateFormatter = DateFormatter()
            dateFormatter.dateFormat = "yyyy-MM-dd'T'HH:mm:ss"
            let timestamp = dateFormatter.string(from: Date())

            let plainText = "Beken packet AES128 " + timestamp
            let encryptedMessageAES = try cryptoManager.encryptAES(plaintext: plainText)
            let message = "\(nameStr) A1 \(encryptedMessageAES)"

            print(message)

            if let data = message.data(using: .utf8) {
                send(data: data)
            } else {
                print("Failed to convert message to data")
            }
        } catch {
            print("Encryption error: \(error)")
        }
    }

    func send(data: Data) {
        connection?.stateUpdateHandler = { state in
            switch state {
            case .ready:
                self.connection?.send(content: data, completion: .contentProcessed { error in
                    if let error = error {
                        print("Failed to send data: \(error)")
                        DispatchQueue.main.async {
                            self.outputMessage = "Failed to send data: \(error.localizedDescription)"
                        }
                    } else {
                        print("Data has been sent")
                        
                        // Update isDataSent on the main thread
                        DispatchQueue.main.async {
                            self.isDataSent = true
                        }
                    }
                })
                
                self.connection?.receiveMessage { data, _, _, error in
                    if let error = error {
                        print("Failed to receive data: \(error)")
                        DispatchQueue.main.async {
                            self.outputMessage = "Failed to receive data: \(error.localizedDescription)"
                        }
                        return
                    }
                    
                    if let data = data, let message = String(data: data, encoding: .utf8) {
                        DispatchQueue.main.async {
                            self.outputMessage = message
                        }
                    }
                }
                
            case .failed(let error):
                if (error as NSError).code == 61 {
                    DispatchQueue.main.async {
                        self.outputMessage = "Connection refused: The server is not accepting connections."
                    }
                } else {
                    print("Connection failed with error: \(error)")
                    DispatchQueue.main.async {
                        self.outputMessage = "Connection failed: \(error.localizedDescription)"
                    }
                }
            default:
                break
            }
        }

        connection?.start(queue: .global())
    }

}
