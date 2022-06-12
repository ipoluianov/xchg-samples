package xchg

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/ipoluianov/gomisc/crypt_tools"
	"github.com/ipoluianov/gomisc/http_tools"
	"io"
	"net/http"
	"sync"
	"time"
)

type Server struct {
	mtx        sync.Mutex
	stopping   bool
	OnReceived func([]byte) ([]byte, error)

	// Local keys
	privateKey    *rsa.PrivateKey
	privateKeyBS  []byte
	privateKey64  string
	privateKeyHex string
	publicKeyBS   []byte
	publicKey64   string
	publicKeyHex  string

	// Connection [ThisNode]<->[XchgHost]
	httpClientReceive *http.Client
	hostingIP         string
	aesKey            []byte
	counter           uint64
	lid               uint64
}

func NewServer(privateKey *rsa.PrivateKey, onRcv func([]byte) ([]byte, error)) *Server {
	var c Server
	c.OnReceived = onRcv
	c.privateKey = privateKey

	// Prepare keys
	c.privateKeyBS = crypt_tools.RSAPrivateKeyToDer(privateKey)
	c.privateKey64 = crypt_tools.RSAPrivateKeyToBase64(privateKey)
	c.privateKeyHex = crypt_tools.RSAPrivateKeyToHex(privateKey)
	c.publicKeyBS = crypt_tools.RSAPublicKeyToDer(&privateKey.PublicKey)
	c.publicKey64 = crypt_tools.RSAPublicKeyToBase64(&privateKey.PublicKey)
	c.publicKeyHex = crypt_tools.RSAPublicKeyToHex(&privateKey.PublicKey)

	// Prepare HTTP-client
	c.httpClientReceive = &http.Client{}
	c.httpClientReceive.Timeout = 60000 * time.Millisecond

	c.Reset()

	return &c
}

func (c *Server) Start() {
	go c.thRcv()
}

func (c *Server) Reset() {
	c.hostingIP = ""
	c.aesKey = nil
	c.counter = 0
	c.lid = 0
}

func (c *Server) getIPsByAddress(_ string) []string {
	return []string{"127.0.0.1"}
}

func (c *Server) findServerForHosting(publicKeyBS []byte) (resultIp string) {
	ips := c.getIPsByAddress(hex.EncodeToString(publicKeyBS))
	for _, ip := range ips {
		code, _, err := http_tools.Request(c.httpClientReceive, "http://"+ip+":8987", map[string][]byte{"f": []byte("i")})
		fmt.Println("Server", ip, "info", code, err)

		if err != nil {
			continue
		}
		if code == 200 {
			fmt.Println("XCHG --- server found: ", ip)
			resultIp = ip
			break
		}
	}
	fmt.Println("XCHG --- findServerForHosting result", resultIp)
	return
}

func (c *Server) requestInit() error {
	var code int
	var data []byte
	var err error

	{
		requestInit1 := make([]byte, 0)
		requestInit1 = append(requestInit1, 0x00) // Init1
		requestInit1 = append(requestInit1, c.publicKeyBS...)

		code, data, err = http_tools.Request(c.httpClientReceive, "http://"+c.hostingIP+":8987", map[string][]byte{"f": []byte("b"), "d": []byte(base64.StdEncoding.EncodeToString(requestInit1))})
		if err != nil {
			fmt.Println("rcv err:", err)
			c.Reset()
			return err
		}
		if code != 200 {
			fmt.Println("code:", code)
			c.Reset()
			return errors.New("code != 200")
		}

		fmt.Println("Received Data init 1:", string(data))

		var encryptedBytes []byte
		var decryptedBytes []byte
		encryptedBytes, err = base64.StdEncoding.DecodeString(string(data))
		if err != nil {
			fmt.Println("ERROR: ", err)
			return err
		}

		decryptedBytes, err = rsa.DecryptPKCS1v15(rand.Reader, c.privateKey, encryptedBytes)
		if err != nil {
			return err
		}
		c.aesKey = decryptedBytes
		fmt.Println("AES: ", hex.EncodeToString(c.aesKey))
		if err != nil {
			return err
		}
	}

	{
		requestInit2 := make([]byte, 1+4)
		requestInit2[0] = 0x01
		binary.LittleEndian.PutUint32(requestInit2[1:], uint32(len(c.publicKeyBS)))
		requestInit2 = append(requestInit2, c.publicKeyBS...)
		var encryptedPublicKey []byte
		encryptedPublicKey, err = crypt_tools.EncryptAESGCM(c.publicKeyBS, c.aesKey)
		if err != nil {
			return err
		}

		requestInit2 = append(requestInit2, encryptedPublicKey...)

		code, data, err = http_tools.Request(c.httpClientReceive, "http://"+c.hostingIP+":8987", map[string][]byte{"f": []byte("b"), "d": []byte(base64.StdEncoding.EncodeToString(requestInit2))})
		if err != nil {
			fmt.Println("rcv err:", err)
			c.Reset()
			return err
		}
		if code != 200 {
			fmt.Println("code:", code, string(data))
			c.Reset()
			return errors.New("code != 200")
		}

		var encryptedBytes []byte
		//var decryptedBytes []byte
		encryptedBytes, err = base64.StdEncoding.DecodeString(string(data))
		if err != nil {
			return err
		}

		var init2Response []byte
		init2Response, err = crypt_tools.DecryptAESGCM(encryptedBytes, c.aesKey)
		if err != nil {
			fmt.Println("1111")
			return err
		}

		if len(init2Response) != 16 {
			fmt.Println("11112222", len(init2Response))
			err = errors.New("len(init2Response) != 8")
			return err
		}

		c.lid = binary.LittleEndian.Uint64(init2Response[0:])
		c.counter = binary.LittleEndian.Uint64(init2Response[8:])

		fmt.Println("lid:", c.lid, "counter:", c.counter)
	}

	return nil
}

func (c *Server) thRcv() {
	var code int
	var data []byte
	var err error

	for !c.stopping {
		if c.hostingIP == "" {
			c.hostingIP = c.findServerForHosting(c.publicKeyBS)
		}

		if c.hostingIP == "" {
			time.Sleep(1 * time.Second)
			c.Reset()
			fmt.Println("no server for hosting found")
			continue
		}

		if len(c.aesKey) != 32 {
			err = c.requestInit()
			if err != nil {
				fmt.Println("XCHG -- no secret bytes", err)
				time.Sleep(1 * time.Second)
				c.Reset()
				continue
			}
		}

		if len(c.aesKey) != 32 {
			time.Sleep(1 * time.Second)
			fmt.Println("XCHG -- no secret bytes")
			c.Reset()
			continue
		}

		var ch cipher.Block
		ch, err = aes.NewCipher(c.aesKey)
		if err != nil {
			time.Sleep(1 * time.Second)
			fmt.Println("XCHG -- cannot create Cipher")
			c.Reset()
			continue
		}
		var gcm cipher.AEAD
		gcm, err = cipher.NewGCM(ch)
		nonce := make([]byte, gcm.NonceSize())
		_, err = io.ReadFull(rand.Reader, nonce)
		if err != nil {
			time.Sleep(1 * time.Second)
			fmt.Println("XCHG -- cannot fill nonce")
			c.Reset()
			continue
		}

		c.counter++

		readRequestBS := make([]byte, 9)
		readRequestBS[0] = 0x02
		binary.LittleEndian.PutUint64(readRequestBS[1:], c.lid)
		counterBS := make([]byte, 8)
		binary.LittleEndian.PutUint64(counterBS, c.counter)
		encryptedCounter := gcm.Seal(nonce, nonce, counterBS, nil)
		readRequestBS = append(readRequestBS, encryptedCounter...)

		fmt.Println("XCHG - READ")
		code, data, err = http_tools.Request(c.httpClientReceive, "http://"+c.hostingIP+":8987", map[string][]byte{"f": []byte("b"), "d": []byte(base64.StdEncoding.EncodeToString(readRequestBS))})
		if err != nil {
			fmt.Println("rcv err:", err)
			c.Reset()
			continue
		}

		if code != 200 && code != 204 {
			c.Reset()
			time.Sleep(1 * time.Second)
			continue
		}

		if code == 200 {
			if len(data) > 0 {
				data, _ = base64.StdEncoding.DecodeString(string(data))
				data, err = crypt_tools.DecryptAESGCM(data, c.aesKey)
				if err != nil {
					fmt.Println("Decrypt error", err)
					c.Reset()
					time.Sleep(1 * time.Second)
					continue
				}
				transactionId := binary.LittleEndian.Uint64(data[0:])
				data = data[8:]
				fmt.Println("Received request", transactionId, string(data))
				response, err := c.OnReceived(data)
				if err != nil {
					continue
				}
				fmt.Println("RESPONSE: ", string(response))

				{
					putRequestBS := make([]byte, 9)
					putRequestBS[0] = 0x03
					binary.LittleEndian.PutUint64(putRequestBS[1:], c.lid)

					responseBS := make([]byte, 8)
					binary.LittleEndian.PutUint64(responseBS, transactionId)
					responseBS = append(responseBS, response...)
					encryptedResponse := gcm.Seal(nonce, nonce, responseBS, nil)

					putRequestBS = append(putRequestBS, encryptedResponse...)
					code, data, err = http_tools.Request(c.httpClientReceive, "http://"+c.hostingIP+":8987", map[string][]byte{"f": []byte("b"), "d": []byte(base64.StdEncoding.EncodeToString(putRequestBS))})
				}

				_ = response
			}

		}
	}
}
