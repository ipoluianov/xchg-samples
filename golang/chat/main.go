package main

import (
	"chat/client"
	"fmt"
)

func onRcv(data []byte) {
	fmt.Println("--- received:", data)
}

func main() {
	cl := client.NewClient("123", onRcv)
	//cl.Send("123", []byte("Hello from myself"))
	for {
		str := ""
		fmt.Println(">")
		fmt.Scanln(&str)
		if str == "1" {
			cl.Send("123", []byte("111"))
		} else {
			cl.Send("123", []byte(str))
		}
	}
}
