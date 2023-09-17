package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"time"

	"github.com/fernet/fernet-go"
)

func main() {

	key := "12345678901234567890123456789012"

	// Encode the key as a base64 string
	base64Key := base64.StdEncoding.EncodeToString([]byte(key))
	fmt.Println("base64 key: " + base64Key)
	//k := fernet.MustDecodeKeys("cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=")
	k := fernet.MustDecodeKeys(base64Key)

	base64tok := os.Args[1]

	// Decode the base64 string
	decodedBytes, err := base64.StdEncoding.DecodeString(base64tok)
	if err != nil {
		fmt.Println("Error decoding base64:", err)
		return
	}

	//tokStr := string(tok)
	//fmt.Println("Encrypted: " + tok)

	msg := fernet.VerifyAndDecrypt([]byte(decodedBytes), 60*time.Second, k)
	fmt.Println(string(msg))

}
