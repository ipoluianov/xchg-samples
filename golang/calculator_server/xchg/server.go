package xchg

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/ipoluianov/gomisc/crypt_tools"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"sync"
	"time"
)

type Server struct {
	mtx               sync.Mutex
	httpClientReceive *http.Client
	xchgIP            string
	stopping          bool
	IPsByAddress      map[string]string
	OnReceived        func([]byte) ([]byte, error)

	// Local keys
	privateKey    *rsa.PrivateKey
	privateKeyBS  []byte
	privateKey64  string
	privateKeyHex string

	publicKeyBS  []byte
	publicKey64  string
	publicKeyHex string

	// AES Key
	aesKey  []byte
	counter uint64
	lid     uint64
}

func NewServer(publicKey string, onRcv func([]byte) ([]byte, error)) *Server {
	var c Server
	c.OnReceived = onRcv
	c.privateKeyBS, _ = base64.StdEncoding.DecodeString(publicKey)

	c.httpClientReceive = &http.Client{}
	c.httpClientReceive.Timeout = 60000 * time.Millisecond

	c.IPsByAddress = make(map[string]string)
	c.xchgIP = ""

	c.generateKeys()

	go c.thRcv()
	return &c
}

func GenerateKey() (privateKey *rsa.PrivateKey, err error) {
	privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	return
}

func RSAPrivateKeyToBase64(privateKey *rsa.PrivateKey) (privateKey64 string) {
	privateKeyBS := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKey64 = base64.StdEncoding.EncodeToString(privateKeyBS)
	return
}

func RSAPrivateKeyFromBase64(privateKey64 string) (privateKey *rsa.PrivateKey, err error) {
	var privateKeyBS []byte
	privateKeyBS, err = base64.StdEncoding.DecodeString(privateKey64)
	if err != nil {
		return
	}
	privateKey, err = x509.ParsePKCS1PrivateKey(privateKeyBS)
	return
}

func RSAPrivateKeyToHex(privateKey *rsa.PrivateKey) (privateKey64 string) {
	privateKeyBS := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKey64 = hex.EncodeToString(privateKeyBS)
	return
}

func RSAPrivateKeyFromHex(privateKey64 string) (privateKey *rsa.PrivateKey, err error) {
	var privateKeyBS []byte
	privateKeyBS, err = hex.DecodeString(privateKey64)
	if err != nil {
		return
	}
	privateKey, err = x509.ParsePKCS1PrivateKey(privateKeyBS)
	return
}

func RSAPublicKeyToBase64(publicKey *rsa.PublicKey) (publicKey64 string) {
	publicKeyBS := x509.MarshalPKCS1PublicKey(publicKey)
	publicKey64 = base64.StdEncoding.EncodeToString(publicKeyBS)
	return
}

func RSAPublicKeyFromBase64(publicKey64 string) (publicKey *rsa.PublicKey, err error) {
	var publicKeyBS []byte
	publicKeyBS, err = base64.StdEncoding.DecodeString(publicKey64)
	if err != nil {
		return
	}
	publicKey, err = x509.ParsePKCS1PublicKey(publicKeyBS)
	return
}

func RSAPublicKeyToHex(publicKey *rsa.PublicKey) (publicKey64 string) {
	publicKeyBS := x509.MarshalPKCS1PublicKey(publicKey)
	publicKey64 = hex.EncodeToString(publicKeyBS)
	return
}

func RSAPublicKeyFromHex(publicKey64 string) (publicKey *rsa.PublicKey, err error) {
	var publicKeyBS []byte
	publicKeyBS, err = hex.DecodeString(publicKey64)
	if err != nil {
		return
	}
	publicKey, err = x509.ParsePKCS1PublicKey(publicKeyBS)
	return
}

func (c *Server) generateKeys() {
	var err error
	privateKeyBS, _ := base64.StdEncoding.DecodeString("MIIEowIBAAKCAQEAw3HnYPGjGltAf1vIw7U8/VrYrAtICk6gPy+K+q+YuQTjYJ8bdc7T5HcshkHpJ5gT9JR9fhC/JhFsRe1ZOV/CxLHYyD0ruo8ouyolC29CSHmeNqRp2TiV8sC642HoTphGRf0MQ0uaq7h7AYdVMxgUUKPgJs5eLI4KQnJa+Dwl0+HUUq54g2qQja4wAgrXhbtm+qm3hcJBycQbuBG2LfGl+lboA7cn0Vo+03QxQlXAp0MBuVOBIQ29PjR2hrq/T6+f48r4XzrUFfrV8iFrQtIq4R33j6UO/88jWcXXnlRAXt4/Eg65W+avBf83UIUVMMtn1QUcpBnyKis2qPF9o+bvCQIDAQABAoIBABfRouQyrrEAm/ypf+8yAEvULYHSIiZ3bJomviZNDizGRru4yEz0NuiqCXgXQkX8B7qP+jdJ7THDf9GJ2ozeecsk7YmBwvmKhulAeqFJHufcQobgRLIfbk7WZDBf90LU1gOjkkIFTcVNx1fpWV3PunIVdrTkA6Akc2WjsCh+lBGdRpB7wrW4KpzKQJNyEo1rSefeS9N55YP13l0WEArIPWIxwe1tJqFdA9pQ345Nt2OO/NUFEFoWpRb17LXeFtXsd/yAQa+1NdnPB7kz8j/G9yD6OkM0mx2tHCcRZDmEtrmstlcZ8mxWj0R6HFJupFEsgJ+tpwwOkXI4zRB6bj1VG30CgYEA4I/HXlgm7tMxVQZld3rZ9sxwZ6/nqbXx0p3A4IqPR+K0xn8oLWSjrzMYBbH1xqBu1Z0BQQUQH6SWHSSn2e92dQnpS2CMXgWXVx2bqCJpF2u7ty0A09qkFuZqop+eZS0qYPAWvufHu/i1IvSP1p32dXygvISEKm/vOaXP6OIdAIcCgYEA3s6XYesRXQrQiBsh5ce0XNDp7bsyCEveQz0cVD+5rA+l2FZF1WNVTt7e0Y5Yzo4kAGQvdkXBMRWYdkz9bjzkZHtR8r3Hgg0G6XXBTO1ooVrdhCEp0Faub4SVNj91IqA0RJO+jmWaEvmASTpN8Mn/zomNFyZsrFyaLiOdulRiR+8CgYEAgwdh7UrCbNgOEO6KhgzI4ZiofdfF9OCVGa+yu1IeCHPfx3KqntH6MGA/xBLytdMm2L2j3ax2nAANFzQsPJ3dIK2H0tOjE7lvdQVxrclmSKQ0A83ejb8lv7bywbEhWyffcnCk1P+pK6UTDDJnO3MwO51crKMl+x0VGS4HAnvtMEECgYA4OzOBhu4O6VfPwelAMLKYajFfykrKRTuHBLlNmfemMRzOCJf/Tt6M1Tqu8JoBJ2Z2otJHqzsixCyCTtP3Km8J3QXFmZfsfpUr/ogWfiRV9LTLUANZjUbg5jkyQ7mwT3ZhiFgjYAkOmOGDma9qAdEJszVkjlIG/if7VQnNqNZVCQKBgHfruxoZplK2BX+ldRGQRiPlos4eDHEc4wfVzD0KghxmtANmGbCa8o2jh3fRLoW9voJ8DKnWh4Eb1ClC6Pu/hK/exPcRYvAV9AhHO5TcEeNjW47pN76KXt+PY2arSkNYI/7OA+l3amLTJchI6Lkwpa2Nu9uPz7Bgn/bzY/Rtc4Uh")
	c.privateKey, err = x509.ParsePKCS1PrivateKey(privateKeyBS)
	if err != nil {
		panic(err)
	}

	//c.privateKey, _ = rsa.GenerateKey(rand.Reader, 2048)

	c.privateKeyBS = x509.MarshalPKCS1PrivateKey(c.privateKey)

	c.publicKeyBS = x509.MarshalPKCS1PublicKey(&c.privateKey.PublicKey)
	c.publicKey64 = base64.StdEncoding.EncodeToString(c.publicKeyBS)
	c.publicKeyHex = hex.EncodeToString(c.publicKeyBS)
	fmt.Println("XCHG --- Address: ", c.publicKey64)
}

func (c *Server) getIPsByAddress(_ string) []string {
	return []string{"127.0.0.1"}
}

func (c *Server) findServerForHosting(publicKeyBS []byte) (resultIp string) {
	//fmt.Println("XCHG --- findServerForHosting", hex.EncodeToString(publicKeyBS))
	ips := c.getIPsByAddress(hex.EncodeToString(publicKeyBS))
	for _, ip := range ips {
		resultIp = ip
		break

		code, _, err := c.Request(c.httpClientReceive, "http://"+ip+":8987", map[string][]byte{"f": []byte("i")})
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

		code, data, err = c.Request(c.httpClientReceive, "http://"+c.xchgIP+":8987", map[string][]byte{"f": []byte("b"), "d": []byte(base64.StdEncoding.EncodeToString(requestInit1))})
		if err != nil {
			fmt.Println("rcv err:", err)
			c.xchgIP = ""
			return err
		}
		if code != 200 {
			fmt.Println("code:", code)
			c.xchgIP = ""
			return errors.New("Code != 200")
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

		code, data, err = c.Request(c.httpClientReceive, "http://"+c.xchgIP+":8987", map[string][]byte{"f": []byte("b"), "d": []byte(base64.StdEncoding.EncodeToString(requestInit2))})
		if err != nil {
			fmt.Println("rcv err:", err)
			c.xchgIP = ""
			return err
		}
		if code != 200 {
			fmt.Println("code:", code, string(data))
			c.xchgIP = ""
			return errors.New("Code != 200")
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
		if c.xchgIP == "" {
			c.xchgIP = c.findServerForHosting(c.publicKeyBS)
		}

		if c.xchgIP == "" {
			time.Sleep(1 * time.Second)
			fmt.Println("no server for hosting found")
			continue
		}

		if len(c.aesKey) != 32 {
			err = c.requestInit()
			if err != nil {
				fmt.Println("XCHG -- no secret bytes", err)
				time.Sleep(1 * time.Second)
				c.xchgIP = ""
				c.aesKey = nil
				c.lid = 0
				c.counter = 0
				continue
			}
		}

		if len(c.aesKey) != 32 {
			time.Sleep(1 * time.Second)
			fmt.Println("XCHG -- no secret bytes")
			c.xchgIP = ""
			c.aesKey = nil
			c.lid = 0
			c.counter = 0
			continue
		}

		var ch cipher.Block
		ch, err = aes.NewCipher(c.aesKey)
		if err != nil {
			time.Sleep(1 * time.Second)
			fmt.Println("XCHG -- cannot create Cipher")
			c.xchgIP = ""
			c.aesKey = nil
			c.counter = 0
			c.lid = 0
			continue
		}
		var gcm cipher.AEAD
		gcm, err = cipher.NewGCM(ch)
		nonce := make([]byte, gcm.NonceSize())
		_, err = io.ReadFull(rand.Reader, nonce)
		if err != nil {
			time.Sleep(1 * time.Second)
			fmt.Println("XCHG -- cannot fill nonce")
			c.xchgIP = ""
			c.aesKey = nil
			c.counter = 0
			c.lid = 0
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
		code, data, err = c.Request(c.httpClientReceive, "http://"+c.xchgIP+":8987", map[string][]byte{"f": []byte("b"), "d": []byte(base64.StdEncoding.EncodeToString(readRequestBS))})
		if err != nil {
			fmt.Println("rcv err:", err)
			c.xchgIP = ""
			continue
		}

		if code != 200 && code != 204 {

			c.xchgIP = ""
			c.aesKey = nil
			c.lid = 0
			time.Sleep(1 * time.Second)
			continue
		}

		if code == 200 {
			if len(data) > 0 {
				data, _ = base64.StdEncoding.DecodeString(string(data))
				data, err = crypt_tools.DecryptAESGCM(data, c.aesKey)
				if err != nil {
					fmt.Println("Decrypt error", err)
					c.xchgIP = ""
					c.aesKey = nil
					c.lid = 0
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
					code, data, err = c.Request(c.httpClientReceive, "http://"+c.xchgIP+":8987", map[string][]byte{"f": []byte("b"), "d": []byte(base64.StdEncoding.EncodeToString(putRequestBS))})
				}

				_ = response
			}

		}
	}
}

func (c *Server) Request(httpClient *http.Client, url string, parameters map[string][]byte) (code int, data []byte, err error) {

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

func (c *Server) Post(httpClient *http.Client, url, contentType string, body io.Reader) (resp *http.Response, err error) {
	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)
	return httpClient.Do(req)
}
