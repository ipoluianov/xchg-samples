package xchg

import "sync"

type BinClientCollection struct {
	binClients    map[string]*BinClient
	binClientsMtx sync.Mutex
}

func NewBinClientCollection() *BinClientCollection {
	var c BinClientCollection
	c.binClients = make(map[string]*BinClient)
	return &c
}

func (c *BinClientCollection) GetBinClient(host string) (client *BinClient) {
	var ok bool
	c.binClientsMtx.Lock()
	client, ok = c.binClients[host]
	if !ok {
		client = NewBinClient(host)
		c.binClients[host] = client
	}
	c.binClientsMtx.Unlock()
	return
}
