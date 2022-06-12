package main

import (
	"calculator_server/xchg"
	"fmt"
	"github.com/ipoluianov/gomisc/crypt_tools"
)

func main() {
	fmt.Println("Calculator server started")

	rsaPrivateKey, _ := crypt_tools.GenerateRSAKey()

	xchgServer := xchg.NewServer(rsaPrivateKey, func(bytes []byte) ([]byte, error) {
		return nil, nil
	})

	xchgServer.Start()

	_, _ = fmt.Scanln()

	fmt.Println("Calculator server stopped")
}
