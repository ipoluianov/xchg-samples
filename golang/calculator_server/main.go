package main

import (
	"calculator_server/app"
	"fmt"
)

func main() {
	fmt.Println("Calculator server started")
	a := app.NewApp()
	a.Start()
	fmt.Println("Calculator server stopped")
}
