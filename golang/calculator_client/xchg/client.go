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
}

func (c *Client) getIPsByAddress(_ string) []string {
	return []string{"127.0.0.1"}
}

func (c *Client) ping() {
	fmt.Println("ping")
	frame := make([]byte, 1)
	frame[0] = 0x05
	frame = append(frame, c.publicKeyBS...)
	code, resp, err := http_tools.Request(c.httpClientSend, "http://"+"127.0.0.1"+":8987", map[string][]byte{"f": []byte("b"), "d": []byte(base64.StdEncoding.EncodeToString(frame))})
	if code == 200 && err == nil {
		c.remoteServerHostingIP = "127.0.0.1"
		respBS, _ := base64.StdEncoding.DecodeString(string(resp))
		fmt.Println("respBS", respBS)
		c.lid = binary.LittleEndian.Uint64(respBS)
	}
	fmt.Println("ping exit ", code, err)
}

func (c *Client) regularCall(frameType byte, data []byte) (resp []byte, err error) {
	var code int
	frame := make([]byte, 9)
	frame[0] = 0x04
	binary.LittleEndian.PutUint64(frame[1:], c.lid)
	frame = append(frame, frameType)
	frame = append(frame, data...)
	code, resp, err = http_tools.Request(c.httpClientSend, "http://"+c.remoteServerHostingIP+":8987", map[string][]byte{"f": []byte("b"), "d": []byte(base64.StdEncoding.EncodeToString(frame))})
	respBS, _ := base64.StdEncoding.DecodeString(string(resp))
	fmt.Println("CALL RESULT", string(respBS))
	if err != nil {
		return
	}
	if code != 200 {
		err = errors.New("error code=" + fmt.Sprint(code))
		return
	}
	return
}

func (c *Client) auth() (err error) {
	var code int
	var resp []byte

	frame := make([]byte, 9)
	frame[0] = 0x04                                 // xchg - to server
	binary.LittleEndian.PutUint64(frame[1:], c.lid) //  LID

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
	frame = append(frame, 0x01)                 // Type: auth frame
	frame = append(frame, encryptedAuthData...) // Data to server

	// Request
	code, resp, err = http_tools.Request(c.httpClientSend, "http://"+c.remoteServerHostingIP+":8987", map[string][]byte{"f": []byte("b"), "d": []byte(base64.StdEncoding.EncodeToString(frame))})
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

	// decrypt auth result by AES key
	var bsAuthResult []byte
	bsAuthResult, err = crypt_tools.DecryptAESGCM(respBS, c.aesKey)
	if err != nil {
		return
	}

	fmt.Println("CALL auth RESULT", string(bsAuthResult))
	if err != nil {
		return
	}

	c.aesKey = respBS

	return
}

func (c *Client) Call(data []byte) (resp []byte, err error) {
	//fmt.Println("Call")
	if len(c.remoteServerHostingIP) == 0 {
		//fmt.Println("Call try ping")
		c.ping()
		c.auth()
	}

	if len(c.remoteServerHostingIP) == 0 {
		//fmt.Println("Call try ping - no")
		err = errors.New("no route to node")
		return
	}

	//fmt.Println("Call executing")
	resp, err = c.regularCall(0, data)
	//fmt.Println("Call executed")
	return
}
