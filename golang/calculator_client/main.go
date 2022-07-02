package main

import (
	"calculator_client/xchg"
	"crypto/rsa"
	"fmt"
	"io/ioutil"
	"time"

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

	client := xchg.NewClient(publicKey, "main password")
	var res []byte

	for i := 0; i < 3; i++ {
		res, err = client.Call([]byte("HELLO1"))
		fmt.Println(string(res), err)
	}

	time.Sleep(10 * time.Second)

	for i := 0; i < 3; i++ {
		res, err = client.Call([]byte("HELLO2"))
		fmt.Println(string(res), err)
	}

	fmt.Println("Calculator client stopped")
}
