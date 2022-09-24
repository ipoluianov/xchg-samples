package xchg

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

type BinClient struct {
	mtx               sync.Mutex
	host              string
	conn              net.Conn
	transactions      map[int32]*BinClientTransaction
	nextTransactionId int32
	maxFrameSize      int
}

type BinClientTransaction struct {
	TransactionId int32
	Request       []byte
	Response      []byte
	Complete      bool
	Err           error
}

func NewBinClientTransaction(id int32, request []byte) *BinClientTransaction {
	var c BinClientTransaction
	c.TransactionId = id
	c.Request = request
	c.Response = nil
	c.Complete = false
	c.Err = nil
	return &c
}

func NewBinClient(host string) *BinClient {
	var c BinClient
	c.host = host
	c.maxFrameSize = 1024 * 1024
	c.transactions = make(map[int32]*BinClientTransaction)
	go c.thReceive()
	return &c
}

func (c *BinClient) thReceive() {
	var n int
	var err error
	incomingData := make([]byte, c.maxFrameSize)
	incomingDataOffset := 0

	for {
		// Check connection
		if c.conn == nil {
			fmt.Println("connecting ...")
			c.conn, err = net.Dial("tcp", c.host+":8484")
			if err != nil {
				fmt.Println("connecting ... error")
				time.Sleep(100 * time.Millisecond)
				continue
			}
			incomingData = make([]byte, c.maxFrameSize)
			incomingDataOffset = 0
			fmt.Println("connecting ... ok")
		}

		// Read
		n, err = c.conn.Read(incomingData[incomingDataOffset:])
		if n < 0 {
			fmt.Println("received <0 bytes")
			c.conn.Close()
			c.conn = nil
			continue
		}
		if err != nil {
			fmt.Println("received err", err)
			c.conn.Close()
			c.conn = nil
			continue
		}
		if n == 77 {
			fmt.Println("received", n, "bytes")
		}

		incomingDataOffset += n
		processedLen := 0
		for {
			// Find Signature
			for processedLen < incomingDataOffset && incomingData[processedLen] != 0xAA {
				processedLen++
			}

			restBytes := incomingDataOffset - processedLen
			if restBytes < 8 {
				break
			}

			// Get header
			signature := binary.LittleEndian.Uint32(incomingData[processedLen:])
			_ = signature
			frameLen := int(binary.LittleEndian.Uint32(incomingData[processedLen+4:]))

			// Check frame size
			if frameLen < 8 || frameLen > c.maxFrameSize {
				// ERROR: wrong frame size
				err = errors.New("wrong frame size")
				break
			}

			if restBytes < frameLen {
				break
			}

			transaction := int32(signature >> 8)

			frame := make([]byte, frameLen-8)
			copy(frame, incomingData[processedLen+8:processedLen+frameLen])
			processedLen += frameLen

			c.setResponse(transaction, frame)
		}

		if err != nil {
			c.conn.Close()
			c.conn = nil
			continue
		}

		for i := processedLen; i < incomingDataOffset; i++ {
			incomingData[i-processedLen] = incomingData[i]
		}
		incomingDataOffset -= processedLen
	}
}

func (c *BinClient) setResponse(transactionId int32, frameData []byte) {
	//fmt.Println("Set Response", transactionId, frameData)
	// Find transaction
	var transaction *BinClientTransaction
	var ok bool
	c.mtx.Lock()
	transaction, ok = c.transactions[transactionId]
	c.mtx.Unlock()
	if !ok || transaction == nil {
		return
	}

	// Get code
	if len(frameData) < 1 {
		transaction.Err = errors.New("wrong frame len")
		transaction.Complete = true
		return
	}
	code := frameData[0]

	// Set response
	if code == 1 {
		transaction.Err = errors.New(string(frameData[1:]))
	} else {
		transaction.Response = frameData[1:]
		//fmt.Println("Transaction OK", transaction.TransactionId)
	}
	transaction.Complete = true
}

func (c *BinClient) Request(frameData []byte) (result []byte, err error) {
	var n int
	var conn net.Conn

	for i := 0; i < 10; i++ {
		c.mtx.Lock()
		conn = c.conn
		c.mtx.Unlock()
		if conn != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if conn == nil {
		err = errors.New("no connection")
		return
	}

	//fmt.Println("Call prepare")
	// Prepare transaction
	c.mtx.Lock()
	c.nextTransactionId++
	if c.nextTransactionId > 16777215 {
		c.nextTransactionId = 1
	}
	transactionId := c.nextTransactionId
	frame := make([]byte, 8+len(frameData))
	signature := uint32(transactionId<<8) | 0xAA
	binary.LittleEndian.PutUint32(frame, signature)
	binary.LittleEndian.PutUint32(frame[4:], uint32(8+len(frameData)))
	copy(frame[8:], frameData)
	transaction := NewBinClientTransaction(transactionId, frame)
	c.transactions[transactionId] = transaction
	c.mtx.Unlock()

	// Send frame
	sentBytes := 0
	for sentBytes < len(frame) {
		n, err = conn.Write(frame[sentBytes:])
		if err != nil {
			break
		}
		if n < 1 {
			break
		}
		sentBytes += n
	}

	if sentBytes != len(frame) {
		err = errors.New("sending request error")
		fmt.Println("sentBytes != len(frame)", err)
		return
	}

	//fmt.Println("SENT ---------------------", transactionId)

	// Wait for response
	timeout := 3 * time.Second
	waitingDurationInMilliseconds := timeout.Milliseconds()
	waitingTick := int64(1)
	waitingIterationCount := waitingDurationInMilliseconds / waitingTick
	for i := int64(0); i < waitingIterationCount; i++ {
		if transaction.Complete {
			err = transaction.Err
			result = transaction.Response
			c.mtx.Lock()
			delete(c.transactions, transactionId)
			c.mtx.Unlock()
			return
		}
		time.Sleep(time.Duration(waitingTick) * time.Millisecond)
	}
	err = errors.New("timeout")
	fmt.Println("TIMEOUT", err)
	result = nil
	c.mtx.Lock()
	delete(c.transactions, transactionId)
	c.mtx.Unlock()
	return
}
