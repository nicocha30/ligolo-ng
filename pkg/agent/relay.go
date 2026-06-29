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
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/allsmog/ligolo-ng-relay/pkg/protocol"
	"github.com/allsmog/ligolo-ng-relay/pkg/relay"
	"github.com/allsmog/ligolo-ng-relay/pkg/tlsutils"
	"github.com/sirupsen/logrus"
)

var (
	relayPendingConns sync.Map // map[int32]net.Conn
	relayConnID       atomic.Int32
	relayListener     net.Listener
	relayMutex        sync.Mutex
)

const (
	relayAuthMagic       = "LIGOLO-RELAY-AUTH\x00"
	relayAuthMaxTokenLen = 4096
	relayAuthTimeout     = 10 * time.Second
	relayAuthMaxInFlight = 64
	relayPendingMax      = 128
)

var (
	relayAuthSlots    = make(chan struct{}, relayAuthMaxInFlight)
	relayPendingSlots = make(chan struct{}, relayPendingMax)
)

func RelayAuthTokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func acquireRelayAuthSlot() bool {
	select {
	case relayAuthSlots <- struct{}{}:
		return true
	default:
		return false
	}
}

func releaseRelayAuthSlot() {
	<-relayAuthSlots
}

func acquireRelayPendingSlot() bool {
	select {
	case relayPendingSlots <- struct{}{}:
		return true
	default:
		return false
	}
}

func releaseRelayPendingSlot() {
	<-relayPendingSlots
}

func WriteRelayAuth(conn net.Conn, token string) error {
	if token == "" {
		return nil
	}
	if len(token) > relayAuthMaxTokenLen {
		return fmt.Errorf("relay auth token is too long")
	}
	payload := make([]byte, 0, len(relayAuthMagic)+2+len(token))
	payload = append(payload, []byte(relayAuthMagic)...)
	payload = binary.BigEndian.AppendUint16(payload, uint16(len(token)))
	payload = append(payload, []byte(token)...)
	_, err := conn.Write(payload)
	return err
}

func verifyRelayAuth(conn net.Conn, expectedHash string, tokenExpiresAtUnix int64) error {
	if expectedHash == "" {
		return nil
	}
	expectedHashBytes, err := hex.DecodeString(expectedHash)
	if err != nil {
		return fmt.Errorf("relay auth hash is invalid: %v", err)
	}
	if len(expectedHashBytes) != sha256.Size {
		return fmt.Errorf("relay auth hash has invalid length")
	}

	_ = conn.SetReadDeadline(time.Now().Add(relayAuthTimeout))
	defer conn.SetReadDeadline(time.Time{})

	magic := make([]byte, len(relayAuthMagic))
	if _, err := io.ReadFull(conn, magic); err != nil {
		return fmt.Errorf("relay auth handshake failed: %v", err)
	}
	if string(magic) != relayAuthMagic {
		return fmt.Errorf("relay auth handshake missing")
	}

	var lengthBuf [2]byte
	if _, err := io.ReadFull(conn, lengthBuf[:]); err != nil {
		return fmt.Errorf("relay auth length read failed: %v", err)
	}
	tokenLen := binary.BigEndian.Uint16(lengthBuf[:])
	if tokenLen == 0 || tokenLen > relayAuthMaxTokenLen {
		return fmt.Errorf("relay auth token length is invalid")
	}

	token := make([]byte, tokenLen)
	if _, err := io.ReadFull(conn, token); err != nil {
		return fmt.Errorf("relay auth token read failed: %v", err)
	}
	if tokenExpiresAtUnix > 0 && time.Now().Unix() >= tokenExpiresAtUnix {
		return fmt.Errorf("relay auth token expired")
	}
	actualHash := sha256.Sum256(token)
	if subtle.ConstantTimeCompare(actualHash[:], expectedHashBytes) != 1 {
		return fmt.Errorf("relay auth token rejected")
	}
	return nil
}

func sendRelayEvent(encoder *protocol.LigoloEncoder, notifyMutex *sync.Mutex, kind, remoteAddr, message string) error {
	notifyMutex.Lock()
	defer notifyMutex.Unlock()
	return encoder.Encode(protocol.RelayEventPacket{
		Kind:       kind,
		RemoteAddr: remoteAddr,
		Message:    message,
		AtUnix:     time.Now().Unix(),
	})
}

// StartRelayListener starts a TLS listener on the given address and notifies
// the proxy of each downstream agent connection via the control stream.
func StartRelayListener(listenAddr string, authTokenHash string, tokenExpiresAtUnix int64, oneTimeToken bool, controlConn net.Conn) error {
	selfcrt := tlsutils.NewSelfCert(nil)
	crt, err := selfcrt.GetCertificate("ligolo-relay")
	if err != nil {
		return fmt.Errorf("relay: could not generate self-signed certificate: %v", err)
	}

	fingerprint := fmt.Sprintf("%X", sha256.Sum256(crt.Certificate[0]))

	tlsCfg := &tls.Config{
		GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return crt, nil
		},
	}

	lis, err := tls.Listen("tcp", listenAddr, tlsCfg)
	if err != nil {
		return fmt.Errorf("relay: could not listen on %s: %v", listenAddr, err)
	}

	relayMutex.Lock()
	relayListener = lis
	relayMutex.Unlock()

	// Send success response with cert fingerprint
	encoder := protocol.NewEncoder(controlConn)
	if err := encoder.Encode(protocol.RelayResponsePacket{
		Err:             false,
		CertFingerprint: fingerprint,
	}); err != nil {
		lis.Close()
		return fmt.Errorf("relay: could not send response: %v", err)
	}

	logrus.Infof("Relay listener started on %s (fingerprint: %s)", listenAddr, fingerprint)

	// Accept downstream agent connections
	go func() {
		// Ensure any connection accepted but never bridged is closed when the
		// accept loop exits (listener closed or control stream broken), so we
		// don't leak file descriptors or goroutines.
		defer drainPendingConns()
		var notifyMutex sync.Mutex
		var oneTimeUsed atomic.Bool
		for {
			conn, err := lis.Accept()
			if err != nil {
				logrus.Debugf("Relay listener closed: %v", err)
				return
			}
			if !acquireRelayAuthSlot() {
				logrus.Warnf("Relay: too many downstream auth handshakes, rejecting %s", conn.RemoteAddr())
				if err := sendRelayEvent(&encoder, &notifyMutex, "auth_overloaded", conn.RemoteAddr().String(), "too many downstream auth handshakes"); err != nil {
					logrus.Debugf("Relay: could not report auth overload: %v", err)
				}
				conn.Close()
				continue
			}

			go func(conn net.Conn) {
				defer releaseRelayAuthSlot()

				if err := verifyRelayAuth(conn, authTokenHash, tokenExpiresAtUnix); err != nil {
					logrus.Warnf("Relay: rejected downstream connection from %s: %v", conn.RemoteAddr(), err)
					if reportErr := sendRelayEvent(&encoder, &notifyMutex, "auth_rejected", conn.RemoteAddr().String(), err.Error()); reportErr != nil {
						logrus.Debugf("Relay: could not report auth rejection: %v", reportErr)
					}
					conn.Close()
					return
				}
				if oneTimeToken && !oneTimeUsed.CompareAndSwap(false, true) {
					logrus.Warnf("Relay: rejected downstream connection from %s: one-time token already used", conn.RemoteAddr())
					if reportErr := sendRelayEvent(&encoder, &notifyMutex, "auth_rejected", conn.RemoteAddr().String(), "one-time relay auth token already used"); reportErr != nil {
						logrus.Debugf("Relay: could not report one-time token rejection: %v", reportErr)
					}
					conn.Close()
					return
				}
				if !acquireRelayPendingSlot() {
					logrus.Warnf("Relay: too many pending downstream connections, rejecting %s", conn.RemoteAddr())
					if reportErr := sendRelayEvent(&encoder, &notifyMutex, "pending_overloaded", conn.RemoteAddr().String(), "too many pending downstream connections"); reportErr != nil {
						logrus.Debugf("Relay: could not report pending overload: %v", reportErr)
					}
					conn.Close()
					return
				}

				connID := relayConnID.Add(1)
				relayPendingConns.Store(connID, conn)

				logrus.Infof("Relay: downstream agent connected from %s (ID: %d)", conn.RemoteAddr(), connID)
				if err := sendRelayEvent(&encoder, &notifyMutex, "downstream_authenticated", conn.RemoteAddr().String(), "downstream relay auth accepted"); err != nil {
					logrus.Debugf("Relay: could not report downstream auth success: %v", err)
				}

				// Notify proxy via control stream. Serialize writes so concurrent
				// downstream auth handshakes cannot interleave msgpack frames.
				notifyMutex.Lock()
				err := encoder.Encode(protocol.RelayNewConnectionPacket{
					ConnectionID: connID,
					RemoteAddr:   conn.RemoteAddr().String(),
				})
				notifyMutex.Unlock()
				if err != nil {
					logrus.Errorf("Relay: could not notify proxy of new connection: %v", err)
					conn.Close()
					removeRelayPendingConn(connID)
					lis.Close()
					return
				}
			}(conn)
		}
	}()

	return nil
}

// HandleRelayBridge bridges a yamux stream from the proxy to a pending downstream connection.
func HandleRelayBridge(bridgeConn net.Conn, connectionID int32) {
	downstreamConn, ok := removeRelayPendingConn(connectionID)
	if !ok {
		logrus.Errorf("Relay bridge: no pending connection with ID %d", connectionID)
		return
	}

	logrus.Infof("Relay bridge: bridging connection ID %d to proxy", connectionID)

	// Bidirectional relay between downstream agent and proxy yamux stream
	relay.StartRelay(downstreamConn, bridgeConn)
}

func removeRelayPendingConn(connectionID int32) (net.Conn, bool) {
	val, ok := relayPendingConns.LoadAndDelete(connectionID)
	if !ok {
		return nil, false
	}
	releaseRelayPendingSlot()
	conn, ok := val.(net.Conn)
	return conn, ok
}

// StopRelayListener stops the relay listener if one is active and closes any
// downstream connections that were accepted but never bridged.
func StopRelayListener() {
	relayMutex.Lock()
	defer relayMutex.Unlock()
	if relayListener != nil {
		relayListener.Close()
		relayListener = nil
		drainPendingConns()
		logrus.Info("Relay listener stopped")
	}
}

// drainPendingConns closes every downstream connection still waiting to be
// bridged and clears the pending map. Safe to call multiple times.
func drainPendingConns() {
	relayPendingConns.Range(func(key, value any) bool {
		if _, loaded := relayPendingConns.LoadAndDelete(key); loaded {
			if conn, ok := value.(net.Conn); ok {
				conn.Close()
			}
			releaseRelayPendingSlot()
		}
		return true
	})
}
