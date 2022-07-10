package xchg

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/ipoluianov/gomisc/crypt_tools"
	"github.com/ipoluianov/gomisc/http_tools"
)

type Client struct {
	mtx               sync.Mutex
	httpClientSend    *http.Client
	httpClientReceive *http.Client
	httpClientPing    *http.Client

	stopping     bool
	IPsByAddress map[string]string

	authData []byte

	// AES Key
	authAESKey []byte
	aesKey     []byte
	counter    uint64

	// Client
	publicKey    *rsa.PublicKey
	publicKeyBS  []byte
	publicKey64  string
	publicKeyHex string

	// State
	remoteServerHostingIP string
	lid                   uint64
	sessionId             uint64

	defaultServer string
}

func NewClient(publicKey *rsa.PublicKey, authString string) *Client {
	var c Client

	//c.defaultServer = "127.0.0.1"
	c.defaultServer = "x01.gazer.cloud"

	c.publicKey = publicKey
	c.publicKeyBS = crypt_tools.RSAPublicKeyToDer(publicKey)
	c.publicKey64 = crypt_tools.RSAPublicKeyToBase64(publicKey)
	c.publicKeyHex = crypt_tools.RSAPublicKeyToHex(publicKey)

	c.httpClientSend = &http.Client{}
	c.httpClientSend.Timeout = 3000 * time.Millisecond

	c.httpClientPing = &http.Client{}
	c.httpClientPing.Timeout = 3000 * time.Millisecond

	c.IPsByAddress = make(map[string]string)

	c.authData = []byte(authString)

	randomBytes := make([]byte, 256)
	_, err := rand.Read(randomBytes)
	if err == nil {
		addrSecretCalculated := sha256.Sum256(randomBytes)
		c.authAESKey = addrSecretCalculated[:]
	}

	c.reset()

	return &c
}

func (c *Client) reset() {
	c.mtx.Lock()
	c.remoteServerHostingIP = ""
	c.lid = 0
	c.sessionId = 0xFFFFFFFFFFFFFFFF
	c.counter = 0
	c.mtx.Unlock()
}

func (c *Client) getIPsByAddress(_ string) []string {
	return []string{c.defaultServer}
}

func (c *Client) ping() (err error) {
	frame := make([]byte, 1)
	frame[0] = 0x05
	frame = append(frame, c.publicKeyBS...)
	var code int
	var resp []byte
	code, resp, err = http_tools.Request(c.httpClientSend, "http://"+c.defaultServer+":8987", map[string][]byte{"f": []byte("b"), "d": []byte(base64.StdEncoding.EncodeToString(frame))})
	if code == 200 && err == nil {
		c.remoteServerHostingIP = c.defaultServer
		var respBS []byte
		respBS, err = base64.StdEncoding.DecodeString(string(resp))
		if err == nil && len(respBS) > 0 {
			if respBS[0] == 0 {
				respBS = respBS[1:]
				fmt.Println("respBS", respBS)
				c.lid = binary.LittleEndian.Uint64(respBS)
			}
		}
	}
	return
}

func (c *Client) regularCall(data []byte, sessionCounter int) (resp []byte, err error) {

	var code int
	frame := make([]byte, 1+8+8)
	frame[0] = 0x04
	binary.LittleEndian.PutUint64(frame[1:], c.lid)
	binary.LittleEndian.PutUint64(frame[9:], c.sessionId)
	var encryptedData []byte
	dataForEncrypt := make([]byte, len(data)+8)
	binary.LittleEndian.PutUint64(dataForEncrypt, uint64(sessionCounter))
	copy(dataForEncrypt[8:], data)
	encryptedData, err = crypt_tools.EncryptAESGCM(dataForEncrypt, c.aesKey)
	frame = append(frame, encryptedData...)
	code, resp, err = http_tools.Request(c.httpClientSend, "http://"+c.remoteServerHostingIP+":8987", map[string][]byte{"f": []byte("b"), "d": []byte(base64.StdEncoding.EncodeToString(frame))})
	respBS, _ := base64.StdEncoding.DecodeString(string(resp))
	if err != nil {
		return
	}
	if code != 200 {
		err = errors.New("error code=" + fmt.Sprint(code))
		return
	}
	if len(respBS) > 0 {
		respBS = respBS[1:]
		resp, err = crypt_tools.DecryptAESGCM(respBS, c.aesKey)
		if err != nil {
			c.reset()
		}
	}
	return
}

func (c *Client) auth() (err error) {
	var code int
	var resp []byte

	if len(c.authAESKey) != 32 {
		err = errors.New("no auth AES key")
		return
	}

	frame := make([]byte, 1+8+8)
	frame[0] = 0x04                                              // xchg - to server
	binary.LittleEndian.PutUint64(frame[1:], c.lid)              //  LID
	binary.LittleEndian.PutUint64(frame[9:], 0xFFFFFFFFFFFFFFFF) //  0xFFFFFFFFFFFFFFFF - unknown session

	// [AES(32)][AUTH_LEN(4)][AUTH_DATA(N)]
	authFrame := make([]byte, 32+4)
	copy(authFrame, c.authAESKey)                              // set AES Key
	authDataLen := uint32(len(c.authData))                     // Getting AUTH_LEN
	binary.LittleEndian.PutUint32(authFrame[32:], authDataLen) // AUTH_LEN
	authFrame = append(authFrame, c.authData...)               // AUTH_DATA

	// Encrypt with public key (address)
	encryptedAuthData, err := rsa.EncryptPKCS1v15(rand.Reader, c.publicKey, authFrame)
	if err != nil {
		return err
	}

	// Prepare frame
	frame = append(frame, encryptedAuthData...) // Data to server

	// Request
	code, resp, err = http_tools.Request(c.httpClientSend, "http://"+c.remoteServerHostingIP+":8987", map[string][]byte{"d": []byte(base64.StdEncoding.EncodeToString(frame))})
	if err != nil {
		return
	}

	// Base64 -> []byte
	respBS, err := base64.StdEncoding.DecodeString(string(resp))
	if err != nil {
		return
	}
	if code != 200 {
		err = errors.New("http error code = " + fmt.Sprint(code))
		return
	}

	if len(respBS) < 1 {
		err = errors.New("wrong xchgx response")
		return
	}

	respBS = respBS[1:]

	// decrypt auth result by AES key
	var bsAuthResult []byte
	bsAuthResult, err = crypt_tools.DecryptAESGCM(respBS, c.authAESKey)
	if err != nil {
		return
	}

	if len(bsAuthResult) != 8+32 {
		err = errors.New("wrong auth response")
	}

	c.sessionId = binary.LittleEndian.Uint64(bsAuthResult)
	c.aesKey = make([]byte, 32)
	copy(c.aesKey, bsAuthResult[8:])

	if c.sessionId == 0xFFFFFFFFFFFFFFFF {
		err = errors.New("wrong auth - error")
	}
	fmt.Println("CALL auth SessionId=", c.sessionId)
	if err != nil {
		return
	}
	return
}

func (c *Client) Call(data []byte) (resp []byte, err error) {
	sessionCounter := 0

	c.mtx.Lock()
	if len(c.remoteServerHostingIP) == 0 {
		err = c.ping()
		if err != nil {
			fmt.Println("PING ERR", err)
			c.remoteServerHostingIP = ""
			c.mtx.Unlock()
			return
		}
		err = c.auth()
		if err != nil {
			fmt.Println("AUTH ERR", err)
			c.remoteServerHostingIP = ""
			c.mtx.Unlock()
			return
		}
	}

	if len(c.remoteServerHostingIP) == 0 {
		err = errors.New("no route to node")
		c.mtx.Unlock()
		return
	}

	c.counter++
	sessionCounter = int(c.counter)
	c.mtx.Unlock()

	//fmt.Println("Call executing")
	resp, err = c.regularCall(data, sessionCounter)
	//fmt.Println("Call executed")
	return
}
