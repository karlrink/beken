//
//  ContentView.swift
//  beken
//
//  Created by Karl Rink on 9/13/23.
//

import SwiftUI
import Network

//import CryptoKit
import Foundation

let appVersion = "0.0.0"

struct ContentView: View {
    
    @AppStorage("serverAddress") private var serverAddress: String = ""
    @AppStorage("serverPort") private var serverPort: String = ""
    
    //@AppStorage("serverAndPortInput") private var serverAndPortInput: String = ""
    
    @AppStorage("nameStr") private var nameStr: String = ""
    @AppStorage("keyStr") private var keyStr: String = ""
    
    //@State private var serverAndPortInput: String = ""
    
    /*
    private var serverAndPort: String {
        get {
            "\(serverAddress):\(serverPort)"
        }
        set {
            let components = newValue.split(separator: ":")
            if let address = components.first {
                serverAddress = String(address)
            }
            if let port = components.last {
                serverPort = String(port)
            }
        }
    }
     */

    @State private var isServerAddressValid: Bool = true
    
    var body: some View {
        NavigationView {
            VStack {
                //Text("Enter Server Information")
                Text("Beken Information")
                    .font(.largeTitle)
                    .padding()

                TextField("Server Address", text: $serverAddress)
                    .textFieldStyle(RoundedBorderTextFieldStyle())
                    .padding()
                
                /*
                TextField("Server Address", text: $serverAddress)
                    .textFieldStyle(RoundedBorderTextFieldStyle())
                    .padding()
                    .onChange(of: serverAddress) { newValue in
                        // Check if the server address is empty
                        isServerAddressValid = !newValue.isEmpty
                    }
                    .background(isServerAddressValid ? Color.clear : Color.red.opacity(0.3))
                    .cornerRadius(5)
                    .overlay(
                        RoundedRectangle(cornerRadius: 5)
                            .stroke(isServerAddressValid ? Color.clear : Color.red, lineWidth: 1)
                    )

                if !isServerAddressValid {
                    Text("Server Address cannot be empty")
                        .font(.footnote)
                        .foregroundColor(.red)
                        .padding(.top, 4)
                }
                */

                

                TextField("Server Port", text: $serverPort)
                    .textFieldStyle(RoundedBorderTextFieldStyle())
                    .keyboardType(.numberPad)
                    .padding()
                
                //TextField("Server:Port", text: $serverAndPortInput)
                //     .textFieldStyle(RoundedBorderTextFieldStyle())
                //     .padding()

                
                TextField("Name", text: $nameStr)
                    .textFieldStyle(RoundedBorderTextFieldStyle())
                    .padding()

                //TextField("Key", text: $keyStr)
                //    .textFieldStyle(RoundedBorderTextFieldStyle())
                //    .keyboardType(.numberPad)
                //    .padding()
                
                SecureField("Key", text: $keyStr)
                    .textFieldStyle(RoundedBorderTextFieldStyle())
                    .keyboardType(.numberPad)
                    .padding()



                NavigationLink(destination: ButtonView(serverAddress: $serverAddress,serverPort: $serverPort, nameStr: $nameStr, keyStr: $keyStr)) {
                    Text("Continue")
                        .font(.headline)
                        .foregroundColor(.white)
                        .padding()
                        .background(Color.blue)
                        .cornerRadius(10)
                }
                .padding()
                .disabled(serverAddress.isEmpty || serverPort.isEmpty || nameStr.isEmpty || keyStr.isEmpty)
                
                // Display the appVersion
                Text("Version: \(appVersion)")
                    .font(.caption)
                    .foregroundColor(.gray)
                    .padding(.top, 20)
                
            }
        }
    }
    
}

struct ButtonView: View {
    
    @State var connection: NWConnection?
    
    @Binding var serverAddress: String
    @Binding var serverPort: String
    @Binding var nameStr: String
    @Binding var keyStr: String
    
    @State private var isDataSent: Bool = false
    @State private var outputMessage: String = ""
    
    // Create an instance of NetworkManager
    //@StateObject private var networkManager = NetworkManager()


    var body: some View {
        VStack {
            //Text("Beken")
            //    .font(.largeTitle)
            //    .padding()

            Button(action: {
                sendUDPDataV1()
                // Call sendUDPData on the networkManager instance
                //networkManager.sendUDPData(nameStr: nameStr, keyStr: keyStr)
            }) {
                //Text("Send UDP Packet")
                Text("Beken")
                    .font(.headline)
                    .foregroundColor(.black)
                    .padding()
                    .background(Color.blue)
                    .cornerRadius(10)
            }
            .padding()

            if isDataSent {
                //Text("Data sent to \(serverAddress):\(serverPort)")
                Text("\(serverAddress):\(serverPort)")
                    .foregroundColor(.green)
                    .font(.headline)
                    .padding()
            }

            if !outputMessage.isEmpty {
                Text(outputMessage)
                    //.foregroundColor(.red)
                    .font(.headline)
                    .padding()
                    .foregroundColor(outputMessage == "fail" ? .red : .green)
            }
            
            // Display the appVersion
            Text("Version: \(appVersion)")
                .font(.caption)
                .foregroundColor(.gray)
                .padding(.top, 20)
            
            
        }
        .navigationBarBackButtonHidden(true)
        .navigationBarHidden(true)
        .onAppear {
            setupUDPConnectionV1()
            // Call setupUDPConnection on the networkManager instance
            //networkManager.setupUDPConnection(serverAddress: serverAddress, serverPort: serverPort)
        }
    }

    //-------
     
    func setupUDPConnectionV1() {
        
        guard let portNumber = UInt16(serverPort) else {
            // Handle the case where serverPort is not a valid port number
            print("Invalid serverPort: \(serverPort)")
            return
        }
        
        connection = NWConnection(
            host: NWEndpoint.Host(serverAddress),
            port: NWEndpoint.Port(rawValue: portNumber)!,
            using: .udp
        )
    }
     
    func sendUDPDataV1() {
        self.outputMessage = "fail"
         
         let trimmedKeyStr = keyStr.trimmingCharacters(in: .whitespacesAndNewlines)
         print(trimmedKeyStr)
       
         //let nonce = "nonce"
         
        //let key = SymmetricKey(size: .bits256) // You can choose the key size you prefer.
        //let cryptoManager = CryptoManager(symmetricKey: key)
        let cryptoManager = CryptoManager(symmetricKeyStr: trimmedKeyStr)

        
        do {
            
            let dateFormatter = DateFormatter()
            dateFormatter.dateFormat = "yyyy-MM-dd'T'HH:mm:ss"
            let timestamp = dateFormatter.string(from: Date())

            
            let plainText = "Beken packet AES128 " + timestamp
            let encryptedMessageAES = try cryptoManager.encryptAES(plaintext: plainText)
            let message = "\(nameStr) A1 \(encryptedMessageAES)"
            
            //let plainText = "Beken packet XOR " + timestamp
            //let encryptedMessageXOR = try cryptoManager.encryptXOR(plaintext: plainText)
            //let message = "\(nameStr) X \(encryptedMessageXOR)"
            
            //let messageTrim = message.trimmingCharacters(in: .whitespacesAndNewlines)
            print(message)
            //print(messageTrim)
            
            //if let data = messageTrim.data(using: .utf8) {
            if let data = message.data(using: .utf8) {
                sendV1(data: data)
            } else {
                print("Failed to convert message to data")
            }
        } catch {
            print("Encryption error: \(error)")
        }
    }


    func sendV1(data: Data) {
        connection?.stateUpdateHandler = { state in
            switch state {
            case .ready:
                // data send
                connection?.send(content: data, completion: .contentProcessed { error in
                    if let error = error {
                        print("Failed to send data: \(error)")
                        DispatchQueue.main.async {
                            self.outputMessage = "Failed to send data: \(error.localizedDescription)"
                        }
                    } else {
                        print("Data has been sent")
                        isDataSent = true
                    }
                })
                
                // data sent, now receive recieve
                
                connection?.receiveMessage { data, _, _, error in
                    
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
