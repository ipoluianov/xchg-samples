package xchg

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/ipoluianov/gomisc/crypt_tools"
	"github.com/ipoluianov/gomisc/http_tools"
)

func (c *Server) requestInit() error {
	var code int
	var data []byte
	var err error

	{
		requestInit1 := make([]byte, 0)
		requestInit1 = append(requestInit1, 0x00) // Init1
		requestInit1 = append(requestInit1, c.publicKeyBS...)

		code, data, err = http_tools.Request(c.httpClientReceive, "http://"+c.hostingIP+":8987", map[string][]byte{"d": []byte(base64.StdEncoding.EncodeToString(requestInit1))})
		if err != nil {
			c.reset()
			return err
		}

		if code != 200 {
			err = errors.New("HTTP error code=" + fmt.Sprint(code) + " Data=" + string(data))
			c.reset()
			return err
		}

		data, err = base64.StdEncoding.DecodeString(string(data))
		if err != nil {
			c.reset()
			return err
		}

		if len(data) < 1 {
			c.reset()
			return err
		}

		if data[0] != 0 {
			err = errors.New("Server error code=" + fmt.Sprint(data[0]) + " Data=" + string(data[1:]))
			c.reset()
			return err
		}

		encryptedBytes := data[1:]

		var decryptedBytes []byte

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

		code, data, err = http_tools.Request(c.httpClientReceive, "http://"+c.hostingIP+":8987", map[string][]byte{"d": []byte(base64.StdEncoding.EncodeToString(requestInit2))})
		if err != nil {
			c.reset()
			return err
		}

		if code != 200 {
			err = errors.New("HTTP error code=" + fmt.Sprint(code) + " Data=" + string(data))
			c.reset()
			return err
		}

		data, err = base64.StdEncoding.DecodeString(string(data))
		if err != nil {
			c.reset()
			return err
		}

		if len(data) < 1 {
			c.reset()
			return err
		}

		if data[0] != 0 {
			err = errors.New("Server error code=" + fmt.Sprint(data[0]) + " Data=" + string(data[1:]))
			c.reset()
			return err
		}

		encryptedBytes := data[1:]

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
