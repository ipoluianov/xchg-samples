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
	aesKey  []byte
	counter uint64

	// Client
	publicKey    *rsa.PublicKey
	publicKeyBS  []byte
	publicKey64  string
	publicKeyHex string

	// State
	remoteServerHostingIP string
	lid                   uint64
	sessionId             uint64
}

func NewClient(publicKey *rsa.PublicKey, authString string) *Client {
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

	c.authData = []byte(authString)

	addrSecretCalculated := sha256.Sum256([]byte("123"))
	c.aesKey = addrSecretCalculated[:]

	c.Reset()

	return &c
}

func (c *Client) Reset() {
	c.remoteServerHostingIP = ""
	c.lid = 0
	c.sessionId = 0
}

func (c *Client) getIPsByAddress(_ string) []string {
	return []string{"127.0.0.1"}
}

func (c *Client) ping() (err error) {
	frame := make([]byte, 1)
	frame[0] = 0x05
	frame = append(frame, c.publicKeyBS...)
	var code int
	var resp []byte
	code, resp, err = http_tools.Request(c.httpClientSend, "http://"+"127.0.0.1"+":8987", map[string][]byte{"f": []byte("b"), "d": []byte(base64.StdEncoding.EncodeToString(frame))})
	if code == 200 && err == nil {
		c.remoteServerHostingIP = "127.0.0.1"
		respBS, _ := base64.StdEncoding.DecodeString(string(resp))
		fmt.Println("respBS", respBS)
		c.lid = binary.LittleEndian.Uint64(respBS)
	}
	return
}

func (c *Client) regularCall(data []byte) (resp []byte, err error) {
	var code int
	frame := make([]byte, 1+8+8)
	frame[0] = 0x04
	binary.LittleEndian.PutUint64(frame[1:], c.lid)
	binary.LittleEndian.PutUint64(frame[9:], c.sessionId)
	frame = append(frame, data...)
	code, resp, err = http_tools.Request(c.httpClientSend, "http://"+c.remoteServerHostingIP+":8987", map[string][]byte{"f": []byte("b"), "d": []byte(base64.StdEncoding.EncodeToString(frame))})
	respBS, _ := base64.StdEncoding.DecodeString(string(resp))
	if err != nil {
		return
	}
	if code != 200 {
		err = errors.New("error code=" + fmt.Sprint(code))
		return
	}
	resp = respBS
	return
}

func (c *Client) auth() (err error) {
	var code int
	var resp []byte

	frame := make([]byte, 1+8+8)
	frame[0] = 0x04                                              // xchg - to server
	binary.LittleEndian.PutUint64(frame[1:], c.lid)              //  LID
	binary.LittleEndian.PutUint64(frame[9:], 0xFFFFFFFFFFFFFFFF) //  0xFFFFFFFFFFFFFFFF - unknown session

	// [AES(32)][AUTH_LEN(4)][AUTH_DATA(N)]
	authFrame := make([]byte, 32+4)
	copy(authFrame, c.aesKey)                                  // set AES Key
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
	code, resp, err = http_tools.Request(c.httpClientSend, "http://"+c.remoteServerHostingIP+":8987", map[string][]byte{"f": []byte("b"), "d": []byte(base64.StdEncoding.EncodeToString(frame))})
	if err != nil {
		return
	}

	fmt.Println("rrr", string(resp))

	// Base64 -> []byte
	respBS, err := base64.StdEncoding.DecodeString(string(resp))
	if err != nil {
		return
	}
	if code != 200 {
		err = errors.New("http error code = " + fmt.Sprint(code))
		return
	}

	// decrypt auth result by AES key
	var bsAuthResult []byte
	bsAuthResult, err = crypt_tools.DecryptAESGCM(respBS, c.aesKey)
	if err != nil {
		return
	}

	if len(bsAuthResult) != 8 {
		err = errors.New("wrong auth response")
	}

	c.sessionId = binary.LittleEndian.Uint64(bsAuthResult)
	fmt.Println("CALL auth SessionId=", c.sessionId)
	if err != nil {
		return
	}
	return
}

func (c *Client) Call(data []byte) (resp []byte, err error) {
	if len(c.remoteServerHostingIP) == 0 {
		err = c.ping()
		if err != nil {
			fmt.Println(err)
			return
		}
		err = c.auth()
		if err != nil {
			fmt.Println(err)
			return
		}
	}

	if len(c.remoteServerHostingIP) == 0 {
		//fmt.Println("Call try ping - no")
		err = errors.New("no route to node")
		return
	}

	//fmt.Println("Call executing")
	resp, err = c.regularCall(data)
	//fmt.Println("Call executed")
	return
}
