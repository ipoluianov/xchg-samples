package xchg

import (
	"errors"
	"fmt"
)

type SnakeCounter struct {
	maxCount      int
	data          []byte
	lastProcessed int
}

func NewSnakeCounter(maxCount int, initValue int) *SnakeCounter {
	var c SnakeCounter
	c.maxCount = maxCount
	c.lastProcessed = -1
	c.data = make([]byte, maxCount)
	for i := 0; i < c.maxCount; i++ {
		c.data[i] = 1
	}
	c.Process(initValue)
	return &c
}

func (c *SnakeCounter) Process(counter int) error {
	if counter < c.lastProcessed-len(c.data) {
		return errors.New("out of limit <")
	}
	if counter > c.lastProcessed {
		shiftRange := counter - c.lastProcessed
		//oldHeader := c.lastProcessed
		newData := make([]byte, c.maxCount)
		for i := 0; i < len(c.data); i++ {
			b := byte(0)
			oldAddressOfCell := i - shiftRange
			if oldAddressOfCell >= 0 && oldAddressOfCell < len(c.data) {
				b = c.data[oldAddressOfCell]
			}
			newData[i] = b
		}
		c.data = newData
		c.data[0] = 1
		c.lastProcessed = counter
		// shift
		return nil
	}

	index := c.lastProcessed - counter
	if index >= 0 && index < c.maxCount {

		if c.data[index] == 0 {
			c.data[c.lastProcessed-counter] = 1
			return nil
		}
	}

	return errors.New("already in use")
}

func (c *SnakeCounter) Print() {
	fmt.Println("--------------------")
	fmt.Println("Header:", c.lastProcessed)
	for i, v := range c.data {
		fmt.Println(c.lastProcessed-i, v)
	}
	fmt.Println("--------------------")
}
