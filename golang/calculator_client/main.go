package main

import (
	"calculator_client/xchg"
	"crypto/rsa"
	"fmt"
	"io/ioutil"

	"github.com/ipoluianov/gomisc/crypt_tools"
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

	client := xchg.NewClient(publicKey, "pass")
	var res []byte
	res, err = client.Call([]byte("HELLO"))
	fmt.Println(string(res))
	res, err = client.Call([]byte("HELLO"))
	fmt.Println(string(res))
	res, err = client.Call([]byte("HELLO"))
	fmt.Println(string(res))

	fmt.Println("Calculator client stopped")
}
