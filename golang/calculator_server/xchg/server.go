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

type Server struct {
	mtx        sync.Mutex
	stopping   bool
	onReceived func(ev ServerEvent) ([]byte, error)

	// Local keys
	privateKey    *rsa.PrivateKey
	privateKeyBS  []byte
	privateKey64  string
	privateKeyHex string
	publicKeyBS   []byte
	publicKey64   string
	publicKeyHex  string

	network *Network

	// Connection [ThisNode]<->[XchgHost]
	httpClientReceive *http.Client
	httpClientPing    *http.Client
	hostingIP         string
	aesKey            []byte
	counter           uint64
	lid               uint64

	// Local runtime
	accessTokens map[string]*AccessToken
	sessionsById map[uint64]*Session
	//sessionsByAuthData map[string]*Session
	nextSessionId uint64

	lastPurgeSessionsTime time.Time
}

type ServerEventType int

const (
	ServerEventNetworkConnected    = 0
	ServerEventNetworkDisconnected = 1
	ServerEventFrame               = 2
	ServerEventAuth                = 3
)

type ServerEvent struct {
	Type ServerEventType
	Data []byte
}

func NewServer(privateKey *rsa.PrivateKey, onRcv func(ev ServerEvent) ([]byte, error)) *Server {
	var c Server
	c.privateKey = privateKey
	c.onReceived = onRcv

	c.network = NewNetwork()

	c.sessionsById = make(map[uint64]*Session)
	//c.sessionsByAuthData = make(map[string]*Session)
	c.accessTokens = make(map[string]*AccessToken)

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

	// Prepare HTTP-client for Ping
	c.httpClientPing = &http.Client{}
	c.httpClientPing.Timeout = 2000 * time.Millisecond

	c.lastPurgeSessionsTime = time.Now()

	// Ready to start
	c.reset()
	return &c
}

func (c *Server) Start() {
	networkDescription := `
=127.0.0.1
b9=192.168.254.12;192.168.254.13;192.168.254.14
	`
	c.network.Load(networkDescription)

	go c.thRcv()
	go c.thPugring()
}

func (c *Server) Stop() {
}

// Reset runtime state
//  - IP of XCHGX
//  - AES-key (LocalServer <-> XCHGX)
//  - LID
func (c *Server) reset() {
	fmt.Println("--- RESET ---")
	c.hostingIP = ""
	c.aesKey = nil
	c.counter = 0
	c.lid = 0
}

func (c *Server) findServerForHosting(publicKeyBS []byte) (resultIp string) {
	ips := c.network.GetAddressesByPublicKey(publicKeyBS)
	for _, ip := range ips {
		fmt.Println("Trying", ip)
		code, _, err := http_tools.Request(c.httpClientPing, "http://"+ip+":8987", map[string][]byte{"f": []byte("i")})
		if err != nil {
			continue
		}
		if code == 200 {
			resultIp = ip
			break
		}
	}
	fmt.Println("HOSTRING IP", resultIp)
	return
}

func (c *Server) thPugring() {
	for !c.stopping {
		c.purgeSessions()
	}
}

func (c *Server) thRcv() {
	var code int
	var data []byte
	var err error

	for !c.stopping {

		// Find server
		if c.hostingIP == "" {
			c.hostingIP = c.findServerForHosting(c.publicKeyBS)
		}
		if c.hostingIP == "" {
			time.Sleep(1 * time.Second)
			c.reset()
			continue
		}

		// Initialization
		if len(c.aesKey) != 32 {
			err = c.requestInit()
			if err != nil {
				time.Sleep(1 * time.Second)
				c.reset()
				continue
			}
		}
		if len(c.aesKey) != 32 {
			time.Sleep(1 * time.Second)
			c.reset()
			continue
		}

		c.counter++

		var encryptedCounter []byte
		counterBS := make([]byte, 8)
		binary.LittleEndian.PutUint64(counterBS, c.counter)
		encryptedCounter, err = crypt_tools.EncryptAESGCM(counterBS, c.aesKey)
		if err != nil {
			c.reset()
			continue
		}

		readRequestBS := make([]byte, 9)
		readRequestBS[0] = 0x02
		binary.LittleEndian.PutUint64(readRequestBS[1:], c.lid)
		readRequestBS = append(readRequestBS, encryptedCounter...)

		fmt.Println("READ", c.counter)
		code, data, err = http_tools.Request(c.httpClientReceive, "http://"+c.hostingIP+":8987", map[string][]byte{"f": []byte("b"), "d": []byte(base64.StdEncoding.EncodeToString(readRequestBS))})
		if err != nil {
			c.reset()
			continue
		}

		if code != 200 && code != 204 {
			c.reset()
			time.Sleep(1 * time.Second)
			continue
		}

		if code == 200 && len(data) > 0 {
			err = c.processFrame(data)
			if err != nil {
				//c.reset()
			}
		}
	}
}

// Processing of incoming frame from XCHGX
func (c *Server) processFrame(data []byte) (err error) {
	data, _ = base64.StdEncoding.DecodeString(string(data))
	data, err = crypt_tools.DecryptAESGCM(data, c.aesKey)
	if err != nil {
		return
	}
	transactionId := binary.LittleEndian.Uint64(data[0:])
	data = data[8:]
	sessionId := binary.LittleEndian.Uint64(data)
	data = data[8:]

	response := make([]byte, 0)

	if sessionId != 0xFFFFFFFFFFFFFFFF {
		// Regular call from remove client
		fmt.Println("Session id received:", sessionId)
		if session, ok := c.sessionsById[sessionId]; ok {
			var ev ServerEvent
			ev.Type = ServerEventFrame
			var decryptedData []byte
			decryptedData, err = crypt_tools.DecryptAESGCM(data, session.aesKey)
			if err == nil {
				ev.Data = decryptedData
				var frameResponse []byte
				frameResponse, err = c.onReceived(ev)
				response, err = crypt_tools.EncryptAESGCM(frameResponse, session.aesKey)
				if err != nil {
					// TODO: error
					fmt.Println("end-to-end encryption error", err)
				}
				session.lastAccessDT = time.Now()
			} else {
				// TODO: error
				fmt.Println("end-to-end decryption error", err)
			}
		} else {
			err = errors.New("wrong sessionId")
		}
	} else {
		fmt.Println("Session id received (-1):", sessionId)

		// Received Init Frame
		// Decrypt by local PrivateKey
		var decryptedData []byte
		decryptedData, err = rsa.DecryptPKCS1v15(rand.Reader, c.privateKey, data)
		if err != nil {
			return
		}

		// AESKEY_AUTH(32 bytes) AuthDataLen(4 bytes) AuthData(AuthDataLen bytes)
		if len(decryptedData) < 32+4 {
			err = errors.New("len(decryptedData) < 32+4")
			return
		}

		// Get authDataLen
		authDataLenU32 := binary.LittleEndian.Uint32(decryptedData[32:])
		authDataLen := int(authDataLenU32)
		if len(decryptedData) != 32+4+authDataLen {
			err = errors.New("len(decryptedData) != 32+4+authDataLen")
			return
		}

		// Get AESKEY
		aesKeyAuth := make([]byte, 32)
		copy(aesKeyAuth, decryptedData)

		// Get AuthData
		authData := make([]byte, authDataLen)
		copy(authData, decryptedData[32+4:])

		// Check AuthData
		var ev ServerEvent
		ev.Type = ServerEventAuth
		ev.Data = authData
		_, err = c.onReceived(ev)

		authResponseBS := make([]byte, 8+32)
		if err == nil {
			fmt.Println("AUTH OK")
			// Auth is OK
			// Create session

			var s *Session
			c.nextSessionId++
			sessionAesKey := sha256.Sum256(authData)
			s = &Session{}
			s.id = c.nextSessionId
			s.aesKey = sessionAesKey[:]
			s.lastAccessDT = time.Now()
			c.sessionsById[s.id] = s

			binary.LittleEndian.PutUint64(authResponseBS, s.id)
			copy(authResponseBS[8:], s.aesKey)
		} else {
			fmt.Println("AUTH ERROR")
			// Auth is not OK
			// Send -1 as SessionId and 'empty' AES Key
			binary.LittleEndian.PutUint64(authResponseBS, 0xFFFFFFFFFFFFFFFF)
			for i := 8; i < 40; i++ {
				authResponseBS[i] = 0
			}
		}

		// Encrypt response by 'AESKEY from client' - end-to-end encryption
		response, err = crypt_tools.EncryptAESGCM(authResponseBS, aesKeyAuth)
		if err != nil {
			return
		}
	}

	{
		// Send response to xchg server
		putRequestBS := make([]byte, 9)
		putRequestBS[0] = 0x03
		binary.LittleEndian.PutUint64(putRequestBS[1:], c.lid)

		responseBS := make([]byte, 8)
		binary.LittleEndian.PutUint64(responseBS, transactionId)
		responseBS = append(responseBS, response...)
		var encryptedResponse []byte
		encryptedResponse, err = crypt_tools.EncryptAESGCM(responseBS, c.aesKey)
		if err != nil {
			return
		}

		putRequestBS = append(putRequestBS, encryptedResponse...)
		_, data, err = http_tools.Request(c.httpClientReceive, "http://"+c.hostingIP+":8987", map[string][]byte{"f": []byte("b"), "d": []byte(base64.StdEncoding.EncodeToString(putRequestBS))})
	}

	_ = response
	return
}

func (c *Server) purgeSessions() {
	now := time.Now()
	if now.Sub(c.lastPurgeSessionsTime).Seconds() > 2 {
		fmt.Println("Purging sessions")
		for sessionId, session := range c.sessionsById {
			if now.Sub(session.lastAccessDT).Seconds() > 2 {
				fmt.Println("Removing session", sessionId)
				delete(c.sessionsById, sessionId)
			}
		}
		c.lastPurgeSessionsTime = time.Now()
	}
}
