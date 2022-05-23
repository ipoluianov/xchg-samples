package main

import (
	"chat/client"
	"encoding/json"
	"fmt"
)

func onRcv(data []byte) {
	fmt.Println("--- received:", data)
}

type Frame struct {
	Src      string `json:"src"`
	Function string `json:"function"`
	Data     []byte `json:"data"`
}

func main() {
	cl := client.NewClient("123", onRcv)

	var fr Frame
	fr.Src = "123"
	fr.Function = "session_open"
	fr.Data = []byte("")

	bs, _ := json.MarshalIndent(fr, "", " ")

	//cl.Send("123", []byte("Hello from myself"))
	for {
		str := ""
		fmt.Println(">")
		fmt.Scanln(&str)
		if str == "1" {
			cl.Send("qwe", bs)
		} else {
			cl.Send("qwe", []byte(str))
		}
	}
}
