package xchg

import "time"

type Session struct {
	id           uint64
	aesKey       []byte
	lastAccessDT time.Time
}
