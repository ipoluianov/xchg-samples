package xchg

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"github.com/ipoluianov/gomisc/crypt_tools"
	"github.com/ipoluianov/gomisc/http_tools"
	"net/http"
	"sync"
	"time"
)

type Client struct {
	mtx               sync.Mutex
	httpClientSend    *http.Client
	httpClientReceive *http.Client
	httpClientPing    *http.Client
	xchgIP            string
	stopping          bool
	IPsByAddress      map[string]string

	// AES Key
	aesKey  []byte
	counter uint64
	lid     uint64

	// Client
	publicKey    *rsa.PublicKey
	publicKeyBS  []byte
	publicKey64  string
	publicKeyHex string
}

func NewClient(publicKey *rsa.PublicKey) *Client {
	var c Client

	c.publicKey = publicKey
	c.publicKeyBS = crypt_tools.RSAPublicKeyToDer(publicKey)
	c.publicKey64 = crypt_tools.RSAPublicKeyToBase64(publicKey)
	c.publicKeyHex = crypt_tools.RSAPublicKeyToHex(publicKey)

	c.httpClientSend = &http.Client{}
	c.httpClientSend.Timeout = 3000 * time.Millisecond

	c.httpClientPing = &http.Client{}
	c.httpClientPing.Timeout = 3000 * time.Millisecond

	c.IPsByAddress = make(map[string]string)
	c.xchgIP = ""

	return &c
}

func (c *Client) getIPsByAddress(_ string) []string {
	return []string{"127.0.0.1"}
}

func (c *Client) findServerByAddress(addr string) (resultIp string) {
	//fmt.Println("findServerByAddress", addr)
	ips := c.getIPsByAddress(addr)
	for _, ip := range ips {
		code, _, err := http_tools.Request(c.httpClientPing, "http://"+ip+":8987", map[string][]byte{"f": []byte("p"), "a": []byte(addr)})
		if err != nil {
			continue
		}
		if code == 200 {
			fmt.Println("server found: ", ip)
			resultIp = ip
			break
		}
	}
	fmt.Println("findServerByAddress result", resultIp)
	return
}

func (c *Client) Call(data []byte) (err error) {
	var ok bool
	var code int
	currentIP := ""
	c.mtx.Lock()
	currentIP, ok = c.IPsByAddress[c.publicKeyHex]
	c.mtx.Unlock()

	needToResend := false

	if ok && currentIP != "" {
		var resp []byte
		//fmt.Println("Send(1): found ip:", currentIP)
		code, resp, err = http_tools.Request(c.httpClientSend, "http://"+currentIP+":8987", map[string][]byte{"f": []byte("w"), "a": []byte(addr), "d": data})
		if err != nil || code != 200 {
			fmt.Println("Send(1) error", err, code, string(resp))
			needToResend = true
			c.mtx.Lock()
			c.IPsByAddress[c.publicKeyHex] = ""
			currentIP = ""
			c.mtx.Unlock()
		} else {
			//fmt.Println("Send(1) OK")
		}
	} else {
		needToResend = true
	}

	if needToResend {
		fmt.Println("resend")
		currentIP = c.findServerByAddress(c.publicKeyHex)
		if currentIP != "" {
			code, _, err = http_tools.Request(c.httpClientSend, "http://"+currentIP+":8987", map[string][]byte{"f": []byte("w"), "a": []byte(addr), "d": data})
			if code == 200 && err == nil {
				c.mtx.Lock()
				c.IPsByAddress[addr] = currentIP
				c.mtx.Unlock()
			}
		} else {
			err = errors.New("no route to host")
		}
	}

	return
}
