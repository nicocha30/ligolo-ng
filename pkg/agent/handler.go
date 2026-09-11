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

package agent

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"os/user"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"

	"github.com/nicocha30/ligolo-ng/pkg/agent/neterror"
	"github.com/nicocha30/ligolo-ng/pkg/agent/smartping"
	"github.com/nicocha30/ligolo-ng/pkg/protocol"
	"github.com/nicocha30/ligolo-ng/pkg/relay"
	"github.com/sirupsen/logrus"
)

// stateMu guards the reverse-listener bookkeeping below (listenerConntrack,
// listenerMap, connTrackID, listenerID). These are accessed concurrently from
// multiple HandleConn goroutines and from each listener's ListenAndServe
// goroutine; without synchronization concurrent map writes crash the agent with
// a fatal "concurrent map writes" runtime error.
var stateMu sync.Mutex
var listenerConntrack map[int32]net.Conn
var listenerMap map[int32]interface{}
var connTrackID int32
var listenerID int32
var sessionID string

// connSem bounds the number of simultaneous outbound relayed connections. It is
// nil (unlimited) unless SetConnectionLimit installs a bounded semaphore. This
// prevents a fast scan from spawning thousands of concurrent dials and
// exhausting the agent's file descriptors.
var connSem chan struct{}

func init() {
	listenerConntrack = make(map[int32]net.Conn)
	listenerMap = make(map[int32]interface{})
	sessionID = hex.EncodeToString(uuid.NodeID())
}

// SetConnectionLimit caps the number of concurrent outbound relayed connections
// the agent will handle at once. A value of n <= 0 means unlimited. It must be
// called once at startup before any connection is accepted.
func SetConnectionLimit(n int) {
	if n > 0 {
		connSem = make(chan struct{}, n)
	} else {
		connSem = nil
	}
}

// registerConn stores an accepted reverse-listener connection under a fresh id
// and returns that id. The store happens before the id is published so a lookup
// racing the publish always finds the connection.
func registerConn(conn net.Conn) int32 {
	stateMu.Lock()
	defer stateMu.Unlock()
	connTrackID++
	id := connTrackID
	listenerConntrack[id] = conn
	return id
}

// getConn returns the tracked connection for id, and whether it was present.
func getConn(id int32) (net.Conn, bool) {
	stateMu.Lock()
	defer stateMu.Unlock()
	conn, ok := listenerConntrack[id]
	return conn, ok
}

// deleteConn removes a tracked connection.
func deleteConn(id int32) {
	stateMu.Lock()
	defer stateMu.Unlock()
	delete(listenerConntrack, id)
}

// registerListener stores a listener under a fresh id and returns that id.
func registerListener(l interface{}) int32 {
	stateMu.Lock()
	defer stateMu.Unlock()
	id := listenerID
	listenerID++
	listenerMap[id] = l
	return id
}

// takeListener removes and returns the listener for id, and whether it existed.
func takeListener(id int32) (interface{}, bool) {
	stateMu.Lock()
	defer stateMu.Unlock()
	l, ok := listenerMap[id]
	if ok {
		delete(listenerMap, id)
	}
	return l, ok
}

// Listener is the base class implementing listener sockets for Ligolo
type Listener struct {
	net.Listener
}

// NewListener register a new listener
func NewListener(network string, addr string) (Listener, error) {
	lis, err := net.Listen(network, addr)
	if err != nil {
		return Listener{}, err
	}
	return Listener{lis}, nil
}

// ListenAndServe fill new listener connections to a channel
func (s *Listener) ListenAndServe(connTrackChan chan int32) error {
	for {
		conn, err := s.Accept()
		if err != nil {
			return err
		}
		connTrackChan <- registerConn(conn)
	}
}

// Close request the main listener to exit
func (s *Listener) Close() error {
	return s.Listener.Close()
}

// UDPListener is the base class implementing UDP listeners for Ligolo
type UDPListener struct {
	*net.UDPConn
}

// NewUDPListener register a new UDP listener
func NewUDPListener(network string, addr string) (UDPListener, error) {
	udpaddr, err := net.ResolveUDPAddr(network, addr)
	if err != nil {
		return UDPListener{}, nil
	}

	udplis, err := net.ListenUDP(network, udpaddr)
	if err != nil {
		return UDPListener{}, err
	}
	return UDPListener{udplis}, err
}

func HandleConn(conn net.Conn) {
	// Close the yamux stream on return for all one-shot request types. Without
	// this, the proxy's FIN only moves the stream to a half-closed state on the
	// agent and it is never reaped from the session, leaking a stream (and its
	// window buffer) per failed probe. Branches that hand conn off to a
	// background relay goroutine set handoff = true to retain ownership; closing
	// an already-closed yamux stream is a no-op, so this is safe on the
	// synchronous relay paths too.
	handoff := false
	defer func() {
		if !handoff {
			_ = conn.Close()
		}
	}()

	decoder := protocol.NewDecoder(conn)
	if err := decoder.Decode(); err != nil {
		logrus.Error(err)
		return
	}

	e := decoder
	switch decoder.Payload.(type) {

	case *protocol.ConnectRequestPacket:
		// Bound concurrent outbound dials/relays to avoid file-descriptor
		// exhaustion during aggressive scanning. The slot is held for the
		// lifetime of the relay and released when HandleConn returns.
		if connSem != nil {
			connSem <- struct{}{}
			defer func() { <-connSem }()
		}
		connRequest := e.Payload.(*protocol.ConnectRequestPacket)
		encoder := protocol.NewEncoder(conn)

		logrus.Debugf("Got connect request to %s:%d", connRequest.Address, connRequest.Port)
		var network string
		if connRequest.Transport == protocol.TransportTCP {
			network = "tcp"
		} else {
			network = "udp"
		}
		if connRequest.Net == protocol.Networkv4 {
			network += "4"
		} else {
			network += "6"
		}

		var d net.Dialer
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		targetConn, err := d.DialContext(ctx, network, fmt.Sprintf("%s:%d", connRequest.Address, connRequest.Port))
		defer cancel()

		var connectPacket protocol.ConnectResponsePacket
		if err != nil {

			var serr syscall.Errno
			if errors.As(err, &serr) {
				// Magic trick ! If the error syscall indicate that the system responded, send back a RST packet!
				if neterror.HostResponded(serr) {
					connectPacket.Reset = true
				}
			}

			connectPacket.Established = false
		} else {
			connectPacket.Established = true
			connectPacket.FramedUDP = connRequest.Transport == protocol.TransportUDP && connRequest.FramedUDP
		}
		if err := encoder.Encode(connectPacket); err != nil {
			logrus.Error(err)
			return
		}
		if connectPacket.Established {
			if connectPacket.FramedUDP {
				relay.StartFramedPacketRelay(conn, targetConn, func(err error) relay.PacketRelayError {
					if neterror.ConnectionRefused(err) {
						return relay.PacketRelayPortUnreachable
					}
					return relay.PacketRelayNoError
				}, nil)
			} else {
				relay.StartRelay(targetConn, conn)
			}
		}
	case *protocol.HostPingRequestPacket:
		pingRequest := e.Payload.(*protocol.HostPingRequestPacket)
		encoder := protocol.NewEncoder(conn)

		pingResponse := protocol.HostPingResponsePacket{Alive: smartping.TryResolve(pingRequest.Address)}

		if err := encoder.Encode(pingResponse); err != nil {
			logrus.Error(err)
			return
		}
	case *protocol.InfoRequestPacket:
		var username string
		encoder := protocol.NewEncoder(conn)
		hostname, err := os.Hostname()
		if err != nil {
			hostname = "UNKNOWN"
		}

		userinfo, err := user.Current()
		if err != nil {
			username = "Unknown"
		} else {
			username = userinfo.Username
		}

		netifaces, err := net.Interfaces()
		if err != nil {
			logrus.Error("could not get network interfaces")
			return
		}
		infoResponse := protocol.InfoReplyPacket{
			Name:       fmt.Sprintf("%s@%s", username, hostname),
			Interfaces: protocol.NewNetInterfaces(netifaces),
			SessionID:  sessionID,
		}

		if err := encoder.Encode(infoResponse); err != nil {
			logrus.Error(err)
			return
		}
	case *protocol.ListenerCloseRequestPacket:
		// Request to close a listener
		closeRequest := e.Payload.(*protocol.ListenerCloseRequestPacket)
		encoder := protocol.NewEncoder(conn)

		var err error
		// takeListener removes the entry under lock; close outside the lock.
		if lis, ok := takeListener(closeRequest.ListenerID); ok {
			if l, ok := lis.(net.Listener); ok {
				l.Close()
			}
			if l, ok := lis.(*net.UDPConn); ok {
				l.Close()
			}
		} else {
			err = errors.New("invalid listener id")
		}

		listenerResponse := protocol.ListenerCloseResponsePacket{
			Err: err != nil,
		}
		if err != nil {
			listenerResponse.ErrString = err.Error()
		}

		if err := encoder.Encode(listenerResponse); err != nil {
			logrus.Error(err)
		}

	case *protocol.ListenerRequestPacket:
		listenRequest := e.Payload.(*protocol.ListenerRequestPacket)
		encoder := protocol.NewEncoder(conn)
		connTrackChan := make(chan int32)
		stopChan := make(chan error)

		if listenRequest.Network == "tcp" {
			listener, err := NewListener(listenRequest.Network, listenRequest.Address)
			if err != nil {
				listenerResponse := protocol.ListenerResponsePacket{
					ListenerID: 0,
					Err:        true,
					ErrString:  err.Error(),
				}
				if err := encoder.Encode(listenerResponse); err != nil {
					logrus.Error(err)
				}
				return
			}
			id := registerListener(listener.Listener)
			listenerResponse := protocol.ListenerResponsePacket{
				ListenerID: id,
				Err:        false,
				ErrString:  "",
			}
			if err := encoder.Encode(listenerResponse); err != nil {
				logrus.Error(err)
			}
			go func() {
				if err := listener.ListenAndServe(connTrackChan); err != nil {
					stopChan <- err
				}
			}()
			defer listener.Close()

		} else if listenRequest.Network == "udp" {
			udplistener, err := NewUDPListener(listenRequest.Network, listenRequest.Address)
			if err != nil {
				listenerResponse := protocol.ListenerResponsePacket{
					ListenerID: 0,
					Err:        true,
					ErrString:  err.Error(),
				}
				if err := encoder.Encode(listenerResponse); err != nil {
					logrus.Error(err)
				}
				return
			}
			id := registerListener(udplistener.UDPConn)
			listenerResponse := protocol.ListenerResponsePacket{
				ListenerID: id,
				Err:        false,
				ErrString:  "",
			}
			if err := encoder.Encode(listenerResponse); err != nil {
				logrus.Error(err)
			}
			// The relay goroutine owns conn for the lifetime of the UDP listener
			// and closes it itself, so skip the deferred close in HandleConn.
			handoff = true
			go func() {
				err := relay.StartUDPListenerRelay(conn, udplistener.UDPConn)
				if err != nil {
					logrus.Error(err)
				}
			}()
		}

		if listenRequest.Network == "tcp" {
			for {
				var bindResponse protocol.ListenerBindReponse
				select {
				case err := <-stopChan:
					logrus.Error(err)
					bindResponse = protocol.ListenerBindReponse{
						SockID:    0,
						Err:       true,
						ErrString: err.Error(),
					}
				case connTrackID := <-connTrackChan:
					bindResponse = protocol.ListenerBindReponse{
						SockID: connTrackID,
						Err:    false,
					}
				}
				if err := encoder.Encode(bindResponse); err != nil {
					logrus.Error(err)
				}

				if bindResponse.Err {
					break
				}

			}
		}
	case *protocol.ListenerSockRequestPacket:
		sockRequest := e.Payload.(*protocol.ListenerSockRequestPacket)
		socketEncDec := protocol.NewEncoderDecoder(conn)

		var sockResponse protocol.ListenerSockResponsePacket
		netConn, ok := getConn(sockRequest.SockID)
		if !ok {
			// Handle error
			sockResponse.ErrString = "invalid or unexistant SockID"
			sockResponse.Err = true
		}

		if err := socketEncDec.Encode(sockResponse); err != nil {
			logrus.Error(err)
			return
		}

		if sockResponse.Err {
			return
		}

		if err := socketEncDec.Decode(); err != nil {
			logrus.Error(err)
			return
		}

		ready, err := protocol.PayloadAs[protocol.ListenerSocketConnectionReady](socketEncDec.Payload)
		if err != nil {
			logrus.Error(err)
			netConn.Close()
			deleteConn(sockRequest.SockID)
			return
		}

		if err := ready.Err; err != false {
			logrus.Debug("Socket relay session failed: error from proxy")
			netConn.Close()
			deleteConn(sockRequest.SockID)
			return
		}

		// Start bidirectional relay; when it returns, close and clean up
		if err := relay.StartRelay(netConn, conn); err != nil {
			logrus.Error(err)
		}
		netConn.Close()
		deleteConn(sockRequest.SockID)

	case *protocol.AgentKillRequestPacket:
		os.Exit(0)

	}
}
