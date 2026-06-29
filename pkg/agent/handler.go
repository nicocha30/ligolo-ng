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

	"github.com/allsmog/ligolo-ng-relay/pkg/agent/neterror"
	"github.com/allsmog/ligolo-ng-relay/pkg/agent/smartping"
	"github.com/allsmog/ligolo-ng-relay/pkg/protocol"
	"github.com/allsmog/ligolo-ng-relay/pkg/relay"
	"github.com/sirupsen/logrus"
)

var listenerConntrack map[int32]net.Conn
var listenerMap map[int32]interface{}
var connTrackID int32
var listenerID int32
var sessionID string
var listenerStateMu sync.Mutex
var reconnectRequestHandler func(protocol.AgentReconnectRequestPacket) error
var reconnectRequestHandlerMu sync.RWMutex

func init() {
	listenerConntrack = make(map[int32]net.Conn)
	listenerMap = make(map[int32]interface{})
	// Allow overriding SessionID for testing multiple agents on the same host
	if envID := os.Getenv("LIGOLO_SESSION_ID"); envID != "" {
		sessionID = envID
	} else {
		sessionID = hex.EncodeToString(uuid.NodeID())
	}
}

func SetReconnectRequestHandler(handler func(protocol.AgentReconnectRequestPacket) error) {
	reconnectRequestHandlerMu.Lock()
	defer reconnectRequestHandlerMu.Unlock()
	reconnectRequestHandler = handler
}

func handleReconnectRequest(request protocol.AgentReconnectRequestPacket) error {
	reconnectRequestHandlerMu.RLock()
	handler := reconnectRequestHandler
	reconnectRequestHandlerMu.RUnlock()
	if handler == nil {
		return errors.New("agent reconnect target updates are not supported")
	}
	return handler(request)
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
		listenerStateMu.Lock()
		connTrackID++
		id := connTrackID
		listenerConntrack[id] = conn
		listenerStateMu.Unlock()
		connTrackChan <- id
	}
}

// Close request the main listener to exit
func (s *Listener) Close() error {
	return s.Listener.Close()
}

func CloseListeners() {
	listenerStateMu.Lock()
	defer listenerStateMu.Unlock()
	for id, lis := range listenerMap {
		switch listener := lis.(type) {
		case net.Listener:
			listener.Close()
		case *net.UDPConn:
			listener.Close()
		}
		delete(listenerMap, id)
	}
	for id, conn := range listenerConntrack {
		conn.Close()
		delete(listenerConntrack, id)
	}
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
	decoder := protocol.NewDecoder(conn)
	if err := decoder.Decode(); err != nil {
		logrus.Error(err)
		return
	}

	e := decoder
	switch decoder.Payload.(type) {

	case *protocol.ConnectRequestPacket:
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
		}
		if err := encoder.Encode(connectPacket); err != nil {
			logrus.Error(err)
			return
		}
		if connectPacket.Established {
			relay.StartRelay(targetConn, conn)
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
			Name:         fmt.Sprintf("%s@%s", username, hostname),
			Interfaces:   protocol.NewNetInterfaces(netifaces),
			SessionID:    sessionID,
			RelayCapable: true,
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
		listenerStateMu.Lock()
		lis, ok := listenerMap[closeRequest.ListenerID]
		if ok {
			delete(listenerMap, closeRequest.ListenerID)
		}
		listenerStateMu.Unlock()
		if ok {
			if l, ok := lis.(net.Listener); ok {
				l.Close()
			}
			if l, ok := lis.(*net.UDPConn); ok {
				l.Close()
			}
			// Remove closed listener from map to avoid leaks
			delete(listenerMap, closeRequest.ListenerID)
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
			listenerStateMu.Lock()
			listenerMap[listenerID] = listener.Listener
			listenerStateMu.Unlock()
			listenerResponse := protocol.ListenerResponsePacket{
				ListenerID: listenerID,
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
			listenerStateMu.Lock()
			listenerMap[listenerID] = udplistener.UDPConn
			listenerStateMu.Unlock()
			listenerResponse := protocol.ListenerResponsePacket{
				ListenerID: listenerID,
				Err:        false,
				ErrString:  "",
			}
			if err := encoder.Encode(listenerResponse); err != nil {
				logrus.Error(err)
			}
			go func() {
				err := relay.StartUDPListenerRelay(conn, udplistener.UDPConn)
				if err != nil {
					logrus.Error(err)
				}
			}()
		}

		listenerID++
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
					return
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
		listenerStateMu.Lock()
		netConn, ok := listenerConntrack[sockRequest.SockID]
		listenerStateMu.Unlock()
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
		if err := socketEncDec.Payload.(*protocol.ListenerSocketConnectionReady).Err; err != false {
			logrus.Debug("Socket relay session failed: error from proxy")
			netConn.Close()
			delete(listenerConntrack, sockRequest.SockID)
			return
		}

		// Start bidirectional relay; when it returns, close and clean up
		if err := relay.StartRelay(netConn, conn); err != nil {
			logrus.Error(err)
		}
		netConn.Close()
		delete(listenerConntrack, sockRequest.SockID)

	case *protocol.AgentKillRequestPacket:
		os.Exit(0)

	case *protocol.AgentReconnectRequestPacket:
		reconnectRequest := e.Payload.(*protocol.AgentReconnectRequestPacket)
		encoder := protocol.NewEncoder(conn)
		response := protocol.AgentReconnectResponsePacket{}
		if err := handleReconnectRequest(*reconnectRequest); err != nil {
			response.Err = true
			response.ErrString = err.Error()
		}
		if err := encoder.Encode(response); err != nil {
			logrus.Error(err)
		}

	case *protocol.RelayRequestPacket:
		relayRequest := e.Payload.(*protocol.RelayRequestPacket)
		encoder := protocol.NewEncoder(conn)

		logrus.Infof("Received relay request for %s", relayRequest.ListenAddr)

		// StartRelayListener sends the RelayResponsePacket itself (with cert fingerprint)
		if err := StartRelayListener(relayRequest.ListenAddr, relayRequest.AuthTokenHash, relayRequest.AuthTokenExpiresAtUnix, relayRequest.OneTimeToken, conn); err != nil {
			logrus.Errorf("Relay start failed: %v", err)
			encoder.Encode(protocol.RelayResponsePacket{
				Err:       true,
				ErrString: err.Error(),
			})
			return
		}

		// Keep the control stream open — it's used for RelayNewConnection notifications.
		// Block until the connection is closed by the proxy.
		buf := make([]byte, 1)
		conn.Read(buf)

		// Control stream closed, stop relay
		StopRelayListener()

	case *protocol.RelayBridgeRequestPacket:
		bridgeRequest := e.Payload.(*protocol.RelayBridgeRequestPacket)
		logrus.Debugf("Received relay bridge request for connection ID %d", bridgeRequest.ConnectionID)

		HandleRelayBridge(conn, bridgeRequest.ConnectionID)

	}
}
