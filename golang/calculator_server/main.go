package main

import (
	"calculator_server/xchg"
	"crypto/rsa"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"time"

	"github.com/ipoluianov/gomisc/crypt_tools"
)

func main() {
	fmt.Println("Calculator server started")

	sc := xchg.NewSnakeCounter(10, 56)
	sc.Print()
	e := sc.Process(50)
	fmt.Println("err:", e)
	sc.Print()
	e = sc.Process(57)
	e = sc.Process(53)
	sc.Print()
	e = sc.Process(59)
	fmt.Println("err:", e)
	sc.Print()

	return

	var privateKey *rsa.PrivateKey

	_, err := os.Stat("private_key.pem")
	if os.IsNotExist(err) {
		privateKey, err = crypt_tools.GenerateRSAKey()
		if err != nil {
			panic(err)
		}
		err = ioutil.WriteFile("private_key.pem", []byte(crypt_tools.RSAPrivateKeyToPem(privateKey)), 0666)
		if err != nil {
			panic(err)
		}
		err = ioutil.WriteFile("public_key.pem", []byte(crypt_tools.RSAPublicKeyToPem(&privateKey.PublicKey)), 0666)
		if err != nil {
			panic(err)
		}
		fmt.Println("Key saved to file")
	} else {
		var bs []byte
		bs, err = ioutil.ReadFile("private_key.pem")
		if err != nil {
			panic(err)
		}
		privateKey, err = crypt_tools.RSAPrivateKeyFromPem(string(bs))
		if err != nil {
			panic(err)
		}
		fmt.Println("Key loaded from file")
	}

	xchgServer := xchg.NewServer(privateKey, func(ev xchg.ServerEvent) (response []byte, err error) {
		switch ev.Type {
		case xchg.ServerEventAuth:
			authString := string(ev.Data)
			if authString != "main password" {
				err = errors.New("wrong aoth data")
			}
			return
		case xchg.ServerEventFrame:
			response = []byte("srvresp=" + time.Now().Format("2016-01-02 15:04:05.999"))
			return
		}
		return
	})

	xchgServer.Start()

	_, _ = fmt.Scanln()

	fmt.Println("Calculator server stopped")
}
