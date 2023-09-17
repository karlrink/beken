package main

import (
	"encoding/base64"
	"fmt"

	"github.com/fernet/fernet-go"
)

func main() {

	key := "12345678901234567890123456789012"

	// Encode the key as a base64 string
	base64Key := base64.StdEncoding.EncodeToString([]byte(key))
	fmt.Println("base64 key: " + base64Key)
	//k := fernet.MustDecodeKeys("cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=")
	k := fernet.MustDecodeKeys(base64Key)

	tok, err := fernet.EncryptAndSign([]byte("hello"), k[0])
	if err != nil {
		panic(err)
	}

	//fmt.Println(tok)
	base64Tok := base64.StdEncoding.EncodeToString([]byte(tok))
	fmt.Println("base64 Encrypted: " + base64Tok)

}
