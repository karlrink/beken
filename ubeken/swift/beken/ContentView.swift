//
//  ContentView.swift
//  beken
//
//  Created by Karl Rink on 9/13/23.
//

import SwiftUI
import Network

struct ContentView: View {
    
    @AppStorage("serverAddress") private var serverAddress: String = ""
    @AppStorage("serverPort") private var serverPort: String = ""
    
    var body: some View {
        NavigationView {
            VStack {
                Text("Enter Server Information")
                    .font(.largeTitle)
                    .padding()
                
                TextField("Server Address", text: $serverAddress)
                    .textFieldStyle(RoundedBorderTextFieldStyle())
                    .padding()
                
                TextField("Server Port", text: $serverPort)
                    .textFieldStyle(RoundedBorderTextFieldStyle())
                    .keyboardType(.numberPad)
                    .padding()
                
                NavigationLink(destination: ButtonView(serverAddress: $serverAddress, serverPort: $serverPort)) {
                    Text("Continue")
                        .font(.headline)
                        .foregroundColor(.white)
                        .padding()
                        .background(Color.blue)
                        .cornerRadius(10)
                }.padding()
            }
        }
    }
    
}

struct ButtonView: View {
    
    @State var connection: NWConnection?
    
    @Binding var serverAddress: String
    @Binding var serverPort: String
    
    @State private var isDataSent: Bool = false
    
    @State private var outputMessage: String = ""
        
    var body: some View {
        VStack {
            Text("Landing Page")
                .font(.largeTitle)
                .padding()
            
            Button(action: {
                // Code to send UDP packet to the server using serverAddress and serverPort
                // You'll need to implement the UDP sending logic here
                
                sendUDPData()
                
            }) {
                Text("Send UDP Packet")
                    .font(.headline)
                    .foregroundColor(.black)
                    .padding()
                    .background(Color.blue)
                    .cornerRadius(10)
            }
            .padding()
            
            if isDataSent {
                //Text("Data has been sent")
                Text("Data has been sent to \(serverAddress):\(serverPort)")
                    .foregroundColor(.green)
                    .font(.headline)
                    .padding()
            }
        }
        .navigationBarBackButtonHidden(true)
        .navigationBarHidden(true)
        
        //if !outputMessage.isEmpty {
        //    Text(outputMessage)
        //        .foregroundColor(.red)
        //        .font(.headline)
        //        .padding()
        //}
        
    }
    
    
    func sendUDPData() {
        let message = "Hello, UDP Server!"
        if let data = message.data(using: .utf8) {
            send(data: data)
        } else {
            NSLog("Failed to convert message to data")
            //self.outputMessage = "Failed to convert message to data"
        }
    }

    func send(data: Data) {
        // Initialize and configure the NWConnection here
        connection = NWConnection(host: NWEndpoint.Host(serverAddress), port: NWEndpoint.Port(serverPort)!, using: .udp)

        connection?.start(queue: .global())

        connection?.send(content: data, completion: .contentProcessed { error in
            if let error = error {
                NSLog("Failed to send data: \(error)")
            } else {
                NSLog("Data has been sent")
                //self.outputMessage = "Hello Data has been sent!"
                isDataSent = true // Update the UI state
            }
        })
    }
    

}
