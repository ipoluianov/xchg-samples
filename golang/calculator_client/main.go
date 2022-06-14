package main

import (
	"calculator_client/xchg"
	"crypto/rsa"
	"fmt"
	"github.com/ipoluianov/gomisc/crypt_tools"
	"io/ioutil"
)

func main() {
	var err error
	var publicKey *rsa.PublicKey
	fmt.Println("Calculator client started")

	var bs []byte
	bs, err = ioutil.ReadFile("public_key.pem")
	if err != nil {
		panic(err)
	}
	publicKey, err = crypt_tools.RSAPublicKeyFromPem(string(bs))
	if err != nil {
		panic(err)
	}
	fmt.Println("Key loaded from file")

	if err != nil {
		panic(err)
	}

	client := xchg.NewClient(publicKey)
	client.Call([]byte("HELLO"))
	client.Call([]byte("HELLO123"))

	fmt.Println("Calculator client stopped")
}
