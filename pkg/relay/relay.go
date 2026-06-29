// Ligolo-ng Relay
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

package relay

import (
	"io"
	"net"
	"sync"
)

// maxUDPDatagramSize is large enough to hold the biggest possible UDP payload,
// so ReadFromUDP never truncates a datagram.
const maxUDPDatagramSize = 65535

func relay(src net.Conn, dst net.Conn, stop chan error, closeOnError bool) {
	_, err := io.Copy(dst, src)
	if closeOnError {
		dst.Close()
		src.Close()
	}

	stop <- err
	return
}

func StartRelay(src net.Conn, dst net.Conn) error {
	stop := make(chan error, 2)

	go relay(src, dst, stop, true)
	go relay(dst, src, stop, true)

	select {
	case err := <-stop:
		return err
	}
}

func StartPacketRelay(src net.Conn, dst net.Conn) error {
	stop := make(chan error, 2)

	go relay(src, dst, stop, true)
	go relay(dst, src, stop, true)

	select {
	case err := <-stop:
		return err
	}
}

// StartUDPListenerRelay relays datagrams between a reverse UDP listener
// (udpConn, an unconnected socket from net.ListenUDP) and the tunnel back to
// the proxy. Unlike StartRelay, it cannot pump raw bytes with io.Copy: the
// listening socket has no fixed peer, so Write always fails and return traffic
// must be sent with WriteToUDP. The address of the most recent client is
// tracked from ReadFromUDP so replies coming back through the tunnel reach it.
//
// Return traffic is routed to the most recently seen client, which serves the
// common single-client case; the listening socket carries no per-client
// demultiplexing, so concurrent clients would share the return path.
func StartUDPListenerRelay(tunnel net.Conn, udpConn *net.UDPConn) error {
	stop := make(chan error, 2)

	var mu sync.Mutex
	var clientAddr *net.UDPAddr

	// Listener -> tunnel: forward client datagrams to the proxy, remembering
	// where each one came from so return traffic can be addressed back.
	go func() {
		buf := make([]byte, maxUDPDatagramSize)
		for {
			n, addr, err := udpConn.ReadFromUDP(buf)
			if n > 0 {
				mu.Lock()
				clientAddr = addr
				mu.Unlock()
				if _, werr := tunnel.Write(buf[:n]); werr != nil {
					stop <- werr
					return
				}
			}
			if err != nil {
				stop <- err
				return
			}
		}
	}()

	// Tunnel -> listener: deliver replies to the last known client using
	// WriteToUDP, since the listening socket is not connected to a peer.
	go func() {
		buf := make([]byte, maxUDPDatagramSize)
		for {
			n, err := tunnel.Read(buf)
			if n > 0 {
				mu.Lock()
				addr := clientAddr
				mu.Unlock()
				if addr != nil {
					if _, werr := udpConn.WriteToUDP(buf[:n], addr); werr != nil {
						stop <- werr
						return
					}
				}
			}
			if err != nil {
				stop <- err
				return
			}
		}
	}()

	err := <-stop
	udpConn.Close()
	tunnel.Close()
	return err
}
