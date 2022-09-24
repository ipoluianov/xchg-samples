package xchg

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/ipoluianov/gomisc/crypt_tools"
)

func (c *Server) requestInit() error {
	var data []byte
	var err error

	{
		requestInit1 := make([]byte, 0)
		requestInit1 = append(requestInit1, 0x00) // Init1
		requestInit1 = append(requestInit1, c.publicKeyBS...)

		data, err = c.Request(c.hostingIP, requestInit1, 1000*time.Millisecond)
		//http_tools.Request(c.httpClientReceive, "http://"+c.hostingIP+":8987", map[string][]byte{"d": []byte(base64.StdEncoding.EncodeToString(requestInit1))})
		if err != nil {
			c.reset()
			return err
		}

		encryptedBytes := data

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

		data, err = c.Request(c.hostingIP, requestInit2, 1000*time.Millisecond)
		if err != nil {
			c.reset()
			return err
		}

		encryptedBytes := data

		var init2Response []byte
		init2Response, err = crypt_tools.DecryptAESGCM(encryptedBytes, c.aesKey)
		if err != nil {
			return err
		}

		if len(init2Response) != 16 {
			err = errors.New("len(init2Response) != 8")
			return err
		}

		c.lid = binary.LittleEndian.Uint64(init2Response[0:])
		c.counter = binary.LittleEndian.Uint64(init2Response[8:])
	}

	return nil
}
