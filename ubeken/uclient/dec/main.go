package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Usage: decrypt <ciphertext>")
		return
	}

	// Load the recipient's private key
	privateKeyPEM := []byte(`
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAzvsvKT3aNqd6TyGT6eBWUqiqcEy8VmV+CWxXL/jNwH8D17mj
j8rxPTCYE7jZAYv1qgKDNAe6TwMrVAbigTvHZJUMGyK4inIEVQPhDgJpjk6YWgKv
mNRJ0STJBkyVLmMVLF8VJREE54Kp/9F6hz+WX3x5oXWJLVVWn2EZ+7UfyUruCfYW
c4Lmj0fRAt1BOWSOsBXvTxNkaoWro9jXglkfpRRyoq3LqsyndSnVVl9ZpyNaMuHX
KIWt7cWKKTMaxJC0Xjd9q25suOC5i141yf/D7cMnz7fDT9accvOEoc774kJGSpIZ
4TJulRvAn/twDBg5r/jNUTIkO0+aWZaha4yLywIDAQABAoIBACmD1jTGdDNMKkse
6AUb+xR/QhheO9R0bPBE68Pyeopmr4WgdX8M7JAiZA5ooBYgVXjxIhHYjvT0JMeo
zduv+tFg19nFgBA8yEOpEIX30+Y4O3SqX0AfLGMnpq59w9pXA1MwCxSxMjOhUKnA
AXyJM4cZd2f8JDSUjlhPaJ/E94gvA5xedMA0PCH4FsrwveunmluSZ5jDqe9CRMAR
XT4h7aeFL3YkBS278pD22+3GoRPbtuaVXBswgfZi23g1RJZ9LaJCimxI+yemnVLl
R9UofAGVl3rM5FPie2Njuyj6hxGtBt7szl6whsYonxHP6niDSX1KDVmDWvQQbcTN
4ZEI11ECgYEA02BMYrR5vLFFOcfApcGmQhmoolEle8GG8QQaDK5cpe1vU++iLviS
+w6vUXyUwZT9cpgUiMBuQg+0ObB2QfS5WVTc8go91gN6uSBDacbiY3RHopvTULj/
k1sVYrwczRgD+ZKuZAoNsdk2g+V7v1oqCCJHKhmOZwbMlDqjb61QMakCgYEA+q1c
owsRGlJ3gRtMa9zn/r4GQTnFbQ2jaP9Tp1+tfRjoHVRtDyfzIPrZ2QDACpgpAYUt
95hvqPZ+LtFBzquLUo5sbgLtaRroNmmw0ZzJVrJbin4G24t4YZwo3flLRoazr1JV
TYCyFBD+bvw6PI6HilRFUv0LeUmOk211+1TUIlMCgYEAgMyG/wY1v9LM+d5L9zS+
mDyGUxHbI0PTc/0p2lxMvBan5Z95VeHFvhE+pwqgoiylGzSsHoATL1HeYeCyzpHO
dy6MyzeOYmAQYcnVChlUTYHHPMByzRdNNH8l0toJOrfNhD/q3654lcxjuY8WDo1k
Wzx33KFh8klkU1Y/zIbw/LECgYEAvON7BWRma8YuRHu0dyaLLdo0Tlvg1w7Kzmhu
uZUP3k6xQMCIOT5qJrS/CJRXIOSNKZcYDxSvNsseQ9rsUnXS0s99Btxv1p4u0imL
0jbpQ8m7zryuICqU+EA6TyD1Rtxjcz2AB5ltFk/D2Q94Nn9TxLlBT4pbZfY2WALI
Py0pd/8CgYBx5OEvuSXYpVLK61vqDcDV3JlCe+OHpEYVHopbUcsn3xUfeqTkoLKS
9PebVOrXm3Tjk9eYq1RXqKvRc9cvaUH/wFF1spBDTnsPQ2fSRvFU0qrhIeZn/k3W
O7wRsDOnu4RK5SBT+uqLsUaw8vPfJS/nXiNOEckmCA4vZj4le858QQ==
-----END RSA PRIVATE KEY-----
`)

	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		fmt.Println("Error decoding private key")
		return
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		fmt.Println("Error parsing private key:", err)
		return
	}

	// Ciphertext from the command line argument
	ciphertext, err := hex.DecodeString(os.Args[1])
	if err != nil {
		fmt.Println("Error decoding ciphertext:", err)
		return
	}

	// Decrypt the data using the private key
	decryptedData, err := rsa.DecryptPKCS1v15(nil, privateKey, ciphertext)
	if err != nil {
		fmt.Println("Error decrypting data:", err)
		return
	}

	fmt.Println("Decrypted data:", string(decryptedData))
}

func loadPrivateKeyFile(privateKeyFile string) (*rsa.PrivateKey, error) {
	// Read the private key file.
	privateKeyData, err := ioutil.ReadFile(privateKeyFile)
	if err != nil {
		return nil, err
	}

	// Parse the private key PEM block.
	block, _ := pem.Decode(privateKeyData)
	if block == nil {
		return nil, fmt.Errorf("failed to parse private key PEM")
	}

	// Parse the private key.
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}
