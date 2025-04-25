// Ligolo-ng
// Copyright (C) 2025 Nicolas Chatelain (nicocha30)

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

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
