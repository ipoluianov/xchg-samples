package client

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"sync"
	"time"
)

type Client struct {
	mtx               sync.Mutex
	httpClientSend    *http.Client
	httpClientReceive *http.Client
	httpClientPing    *http.Client
	localAddrIP       string
	localAddr         string
	stopping          bool
	IPsByAddress      map[string]string
	OnReceived        func([]byte)
}

func NewClient(localAddr string, onRcv func([]byte)) *Client {
	var c Client
	c.localAddr = localAddr
	c.OnReceived = onRcv

	c.httpClientSend = &http.Client{}
	c.httpClientSend.Timeout = 3000 * time.Millisecond

	c.httpClientReceive = &http.Client{}
	c.httpClientReceive.Timeout = 60000 * time.Millisecond

	c.httpClientPing = &http.Client{}
	c.httpClientPing.Timeout = 3000 * time.Millisecond

	c.IPsByAddress = make(map[string]string)
	c.localAddrIP = ""
	go c.thRcv()
	return &c
}

func (c *Client) getIPsByAddress(_ string) []string {
	return []string{"51.195.116.147", "51.195.119.145"}
}

func (c *Client) findServerForHosting(addr string) (resultIp string) {
	fmt.Println("findServerForHosting")
	ips := c.getIPsByAddress(addr)
	for _, ip := range ips {
		code, _, err := c.Request(c.httpClientPing, "http://"+ip+":8987", map[string][]byte{"f": []byte("i")})
		if err != nil {
			continue
		}
		if code == 200 {
			fmt.Println("server found: ", ip)
			resultIp = ip
			break
		}
	}
	fmt.Println("findServerForHosting result", resultIp)
	return
}

func (c *Client) findServerByAddress(addr string) (resultIp string) {
	fmt.Println("findServerByAddress")
	ips := c.getIPsByAddress(addr)
	for _, ip := range ips {
		code, _, err := c.Request(c.httpClientPing, "http://"+ip+":8987", map[string][]byte{"f": []byte("p"), "a": []byte(addr)})
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

func (c *Client) Send(addr string, data []byte) (err error) {
	fmt.Println("Send to", addr, "data", data)
	var ok bool
	var code int
	currentIP := ""
	c.mtx.Lock()
	currentIP, ok = c.IPsByAddress[addr]
	c.mtx.Unlock()

	needToResend := false

	if ok && currentIP != "" {
		fmt.Println("Send(1): found ip:", currentIP)
		code, _, err = c.Request(c.httpClientSend, "http://"+currentIP+":8987", map[string][]byte{"f": []byte("w"), "a": []byte(addr), "d": data})
		if err != nil || code != 200 {
			fmt.Println("Send(1) error", err, code)
			needToResend = true
			c.mtx.Lock()
			c.IPsByAddress[addr] = ""
			currentIP = ""
			c.mtx.Unlock()
		} else {
			fmt.Println("Send(1) OK")
		}
	} else {
		needToResend = true
	}

	if needToResend {
		fmt.Println("resend")
		currentIP = c.findServerByAddress(addr)
		if currentIP != "" {
			code, _, err = c.Request(c.httpClientSend, "http://"+currentIP+":8987", map[string][]byte{"f": []byte("w"), "a": []byte(addr), "d": data})
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

func (c *Client) thRcv() {
	var code int
	var data []byte
	var err error
	for !c.stopping {
		if c.localAddrIP == "" {
			c.localAddrIP = c.findServerForHosting(c.localAddrIP)
		}

		if c.localAddrIP == "" {
			time.Sleep(1 * time.Second)
			fmt.Println("no server for hosting found")
			continue
		}

		code, data, err = c.Request(c.httpClientReceive, "http://"+c.localAddrIP+":8987", map[string][]byte{"f": []byte("r"), "a": []byte(c.localAddr)})
		if err != nil {
			fmt.Println("rcv err:", err)
			c.localAddrIP = ""
			continue
		}
		if code == 204 {
			continue
		}

		c.OnReceived(data)
	}
}

func (c *Client) Request(httpClient *http.Client, url string, parameters map[string][]byte) (code int, data []byte, err error) {

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	for key, value := range parameters {
		var fw io.Writer
		fw, err = writer.CreateFormField(key)
		if err != nil {
			return
		}
		_, err = fw.Write(value)
		if err != nil {
			return
		}
	}
	err = writer.Close()
	if err != nil {
		return
	}
	var response *http.Response
	response, err = c.Post(httpClient, url, writer.FormDataContentType(), &body)
	if err != nil {
		return
	}
	code = response.StatusCode
	data, err = ioutil.ReadAll(response.Body)
	if err != nil {
		_ = response.Body.Close()
		return
	}
	_ = response.Body.Close()
	return
}

func (c *Client) Post(httpClient *http.Client, url, contentType string, body io.Reader) (resp *http.Response, err error) {
	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)
	return httpClient.Do(req)
}
