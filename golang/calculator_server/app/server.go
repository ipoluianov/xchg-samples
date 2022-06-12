package app

import "calculator_server/xchg"

type XchgService struct {
	xchgServer *xchg.Server
}

func NewXchgService() *XchgService {
	var c XchgService
	c.xchgServer = xchg.NewServer()
	return &c
}

func (c *XchgService) Start() {
}
