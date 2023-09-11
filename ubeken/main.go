package main

import (
	"fmt"
	"net"
)

func main() {
	// Define the address to listen on
	address := ":9480"

	// Resolve the UDP address
	udpAddr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		fmt.Println("Error resolving UDP address:", err)
		return
	}

	// Create a UDP connection
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		fmt.Println("Error creating UDP connection:", err)
		return
	}
	defer conn.Close()

	fmt.Println("UDP server listening on", address)

	// Create a buffer to hold incoming data
	buffer := make([]byte, 1024)

	for {
		// Read data from the connection
		n, addr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			fmt.Println("Error reading from UDP connection:", err)
			return
		}

		// Print the received data
		receivedData := buffer[:n]

		fmt.Printf("Received UDP packet from %s: %s\n", addr, receivedData)
	}
}
