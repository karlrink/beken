package main

import (
	"fmt"
	"net"
	"os"
)

func main() {
	// Define the destination address and port
	//destination := "localhost:9480"
	destination := os.Args[1]

	// Create a UDP address structure for the destination
	udpAddr, err := net.ResolveUDPAddr("udp", destination)
	if err != nil {
		fmt.Println("Error resolving UDP address:", err)
		return
	}

	// Create a UDP connection to the destination
	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		fmt.Println("Error creating UDP connection:", err)
		return
	}
	defer conn.Close()

	// Define the data to send
	data := []byte("my udp data")

	// Send the custom UDP packet to the destination
	_, err = conn.Write(data)
	if err != nil {
		fmt.Println("Error sending UDP packet:", err)
		return
	}

	fmt.Println("Custom UDP packet sent to", destination)
}
