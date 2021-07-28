package netstack

import (
	"errors"
	"sync"
)

type ConnPool struct {
	CloseChan chan interface{}
	Pool      chan TunConn
	sync.Mutex
}

func NewConnPool(size int) ConnPool {
	return ConnPool{CloseChan: make(chan interface{}), Pool: make(chan TunConn, size)}
}
func (p *ConnPool) Add(packet TunConn) error {
	p.Lock()
	defer p.Unlock()

	select {
	case <-p.CloseChan:
		return errors.New("pool is closed")
	default:
		p.Pool <- packet
	}
	return nil
}

func (p *ConnPool) Close() error {
	p.Lock()
	defer p.Unlock()

	select {
	case <-p.CloseChan:
		return errors.New("pool is already closed")
	default:
		close(p.CloseChan)
		close(p.Pool)
		p.Pool = nil
	}
	return nil
}

func (p *ConnPool) Closed() bool {
	select {
	case <-p.CloseChan:
		return true
	default:
		return false
	}
}

func (p *ConnPool) Get() (TunConn, error) {
	p.Lock()
	defer p.Unlock()
	select {
	case <-p.CloseChan:
		return TunConn{}, errors.New("pool is closed")
	case tunconn := <-p.Pool:
		return tunconn, nil
	}
}
