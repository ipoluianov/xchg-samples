package xchg

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/ipoluianov/gomisc/crypt_tools"
)

type Server struct {
	mtx        sync.Mutex
	started    bool
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

	// Local runtime
	hostingIP string
	aesKey    []byte
	counter   uint64
	lid       uint64

	sessionsById  map[uint64]*Session
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

	// Prepare keys
	c.privateKeyBS = crypt_tools.RSAPrivateKeyToDer(privateKey)
	c.privateKey64 = crypt_tools.RSAPrivateKeyToBase64(privateKey)
	c.privateKeyHex = crypt_tools.RSAPrivateKeyToHex(privateKey)
	c.publicKeyBS = crypt_tools.RSAPublicKeyToDer(&privateKey.PublicKey)
	c.publicKey64 = crypt_tools.RSAPublicKeyToBase64(&privateKey.PublicKey)
	c.publicKeyHex = crypt_tools.RSAPublicKeyToHex(&privateKey.PublicKey)

	// Prepare HTTP-client
	c.httpClientReceive = &http.Client{}
	c.httpClientReceive.Timeout = 20 * time.Second

	c.lastPurgeSessionsTime = time.Now()

	// Ready to start
	c.fastReset()
	return &c
}

func (c *Server) Start() {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	if c.started {
		return
	}

	networkDescription := `
=127.0.0.1
bb=x01.gazer.cloud
	`
	c.network.Load(networkDescription)

	go c.thRcv()
	go c.thPugring()
	c.started = true
}

func (c *Server) Stop() {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	if !c.started || c.stopping {
		return
	}
	c.stopping = true
	dtStopBegin := time.Now()
	for time.Now().Sub(dtStopBegin).Milliseconds() < 500 && c.started {
		time.Sleep(10)
	}
}

// Reset runtime state
//  - IP of XCHGX
//  - AES-key (LocalServer <-> XCHGX)
//  - LID
func (c *Server) reset() {
	c.waitDurationOrStopping(500 * time.Millisecond)
	c.fastReset()
}

func (c *Server) fastReset() {
	c.mtx.Lock()
	c.hostingIP = ""
	c.aesKey = nil
	c.counter = 0
	c.lid = 0
	c.mtx.Unlock()
}

func (c *Server) findServerForHosting(publicKeyBS []byte) (resultIp string) {
	ips := c.network.GetAddressesByPublicKey(publicKeyBS)
	for _, ip := range ips {
		fmt.Println("Trying", ip)
		request := make([]byte, 1)
		request[0] = 6
		_, err := c.Request(ip, request, 1000*time.Millisecond)
		if err != nil {
			continue
		}
		resultIp = ip
	}
	return
}

func (c *Server) thPugring() {
	for !c.stopping {
		c.purgeSessions()
		c.waitDurationOrStopping(1000 * time.Millisecond)
	}
}

func (c *Server) Request(host string, frameData []byte, timeout time.Duration) (result []byte, err error) {
	GetBinClient(host).srv = c
	result, err = GetBinClient(host).Request(frameData, timeout)
	return
}

func (c *Server) waitDurationOrStopping(duration time.Duration) {
	dtBegin := time.Now()
	for time.Now().Sub(dtBegin).Milliseconds() < duration.Milliseconds() && !c.stopping {
		time.Sleep(100)
	}
}

func (c *Server) thRcv() {
	var err error

	for !c.stopping {

		// Find server
		if c.hostingIP == "" {
			c.hostingIP = c.findServerForHosting(c.publicKeyBS)
		}
		if c.hostingIP == "" {
			c.waitDurationOrStopping(1 * time.Second)
			c.reset()
			continue
		}

		// Initialization
		if len(c.aesKey) != 32 {
			err = c.requestInit()
			if err != nil {
				c.waitDurationOrStopping(1 * time.Second)
				c.reset()
				continue
			}
		}
		if len(c.aesKey) != 32 {
			c.waitDurationOrStopping(1 * time.Second)
			c.reset()
			continue
		}

		time.Sleep(1 * time.Second)

		c.counter++

		var encryptedCounter []byte
		counterBS := make([]byte, 12)
		binary.LittleEndian.PutUint64(counterBS, c.counter)
		binary.LittleEndian.PutUint32(counterBS[8:], 1024*1024)
		encryptedCounter, err = crypt_tools.EncryptAESGCM(counterBS, c.aesKey)
		if err != nil {
			c.reset()
			continue
		}

		readRequestBS := make([]byte, 1+8)
		readRequestBS[0] = 0x02
		binary.LittleEndian.PutUint64(readRequestBS[1:], c.lid)
		readRequestBS = append(readRequestBS, encryptedCounter...)

		var dataBS []byte
		dataBS, err = c.Request(c.hostingIP, readRequestBS, 60*time.Second)
		if err != nil {
			c.reset()
			continue
		}

		if len(dataBS) > 0 {
			go c.processFrames(dataBS)
		}
	}
}

func (c *Server) processRegularCall(transactionId uint64, sessionId uint64, data []byte) {
	var err error
	var response []byte

	c.mtx.Lock()
	session, ok := c.sessionsById[sessionId]
	c.mtx.Unlock()

	if ok {
		var ev ServerEvent
		ev.Type = ServerEventFrame
		var decryptedData []byte
		decryptedData, err = crypt_tools.DecryptAESGCM(data, session.aesKey)
		if err == nil {
			if len(decryptedData) >= 8 {
				sessionCounter := binary.LittleEndian.Uint64(decryptedData)
				err = session.snakeCounter.TestAndDeclare(int(sessionCounter))
				if err == nil {
					ev.Data = decryptedData[8:]
					var frameResponse []byte
					frameResponse, err = c.onReceived(ev)
					response, err = crypt_tools.EncryptAESGCM(frameResponse, session.aesKey)
					if err != nil {
						// TODO: error
						fmt.Println("end-to-end encryption error", err)
					}
					session.lastAccessDT = time.Now()
				} else {
					fmt.Println("!!!!!!!!!!!!!!! wrong session counter !!!!!!!!!!!!!!!!!!!!!!!!!!!!", sessionCounter)
				}
			} else {
				fmt.Println("no session counter")
			}
		} else {
			// TODO: error
			fmt.Println("end-to-end decryption error", err)
		}
	} else {
		err = errors.New("wrong sessionId")
	}

	c.sendResponse(transactionId, response)
}

func (c *Server) processAuth(transactionId uint64, sessionId uint64, data []byte) {
	response := make([]byte, 0)
	var err error

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

		c.mtx.Lock()
		s := &Session{}
		s.snakeCounter = NewSnakeCounter(256, 0)
		c.nextSessionId++
		sessionAesKey := sha256.Sum256(authData)
		s.id = c.nextSessionId
		s.aesKey = sessionAesKey[:]
		s.lastAccessDT = time.Now()
		c.sessionsById[s.id] = s
		c.mtx.Unlock()

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
	c.sendResponse(transactionId, response)
}

// Processing of incoming frame from XCHGX
func (c *Server) processFrames(data []byte) (err error) {
	/*data, err = crypt_tools.DecryptAESGCM(data, c.aesKey)
	if err != nil {
		return
	}*/
	counter := 0

	//originalSize := len(data)

	for len(data) > 0 {
		if len(data) < 12 {
			break
		}
		frameSize := int(binary.LittleEndian.Uint32(data[0:]))
		if frameSize > len(data) {
			break
		}

		transactionId := binary.LittleEndian.Uint64(data[4:])
		data = data[12:]
		sessionId := binary.LittleEndian.Uint64(data)
		data = data[8:]

		if sessionId != 0xFFFFFFFFFFFFFFFF {
			// Regular call from remove client
			//fmt.Println("SessionID:", sessionId)
			go c.processRegularCall(transactionId, sessionId, data[:frameSize-20])
		} else {
			go c.processAuth(transactionId, sessionId, data[:frameSize-20])
		}
		counter++
		data = data[frameSize-20:]
	}

	//fmt.Println("Processing frames =", counter, "size =", originalSize)

	return
}

func (c *Server) sendResponse(transactionId uint64, response []byte) {
	var err error
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
	c.Request(c.hostingIP, putRequestBS, 1*time.Second)
}

func (c *Server) purgeSessions() {
	now := time.Now()
	c.mtx.Lock()
	if now.Sub(c.lastPurgeSessionsTime).Seconds() > 5*60 {
		fmt.Println("Purging sessions")
		for sessionId, session := range c.sessionsById {
			if now.Sub(session.lastAccessDT).Seconds() > 30 {
				fmt.Println("Removing session", sessionId)
				delete(c.sessionsById, sessionId)
			}
		}
		c.lastPurgeSessionsTime = time.Now()
	}
	c.mtx.Unlock()
}
