package main

import (
	"calculator_client/xchg"
	"crypto/rsa"
	"fmt"
	"io/ioutil"
	"math/rand"
	"sync"
	"time"

	"github.com/ipoluianov/gomisc/crypt_tools"
)

var mtx sync.Mutex
var callCounter int
var lastStatCounter int
var lastStatDT time.Time

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

	var fn = func(th string) {
		client := xchg.NewClient(publicKey, "main password")
		content := make([]byte, 1*1024)
		for i := 0; i < len(content); i++ {
			content[i] = byte(i)
		}
		var res []byte
		for i := 0; i < 10000; i++ {
			//dt1 := time.Now()
			res, err = client.Call(content)
			if err != nil {
				fmt.Println("ERROR:", err)
			}
			_ = res
			//dt2 := time.Now()
			//fmt.Println(">", string(res), dt2.Sub(dt1).Milliseconds(), err)
			mtx.Lock()
			callCounter++
			mtx.Unlock()
			//time.Sleep(100 * time.Millisecond)
		}
	}

	lastStatDT = time.Now()
	for j := 0; j < 100; j++ {
		time.Sleep(time.Duration((rand.Int()%10)+300) * time.Millisecond)
		go fn("@" + fmt.Sprint(j))
	}

	for {
		mtx.Lock()
		now := time.Now()
		duration := now.Sub(lastStatDT).Seconds()
		lastStatDT = time.Now()
		fmt.Println("================ STAT ===============")
		count := callCounter - lastStatCounter
		fmt.Println("COUNT:", count)
		fmt.Println("Speed: ", float64(count)/duration, "calls / sec")
		lastStatCounter = callCounter
		mtx.Unlock()

		time.Sleep(1 * time.Second)
	}

	fmt.Println("clients started")
	fmt.Scanln()

	//time.Sleep(3 * time.Second)

	fmt.Println("Calculator client stopped")
}
