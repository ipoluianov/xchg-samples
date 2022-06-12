package main

import (
	"calculator_client/xchg"
	"fmt"
)

func main() {
	fmt.Println("Calculator client started")

	client := xchg.NewClient()
	client.Send()

	fmt.Println("Calculator client stopped")
}
