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
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"sync/atomic"

	"github.com/nicocha30/ligolo-ng/pkg/protocol"
	"github.com/nicocha30/ligolo-ng/pkg/relay"
	"github.com/nicocha30/ligolo-ng/pkg/tlsutils"
	"github.com/sirupsen/logrus"
)

var (
	relayPendingConns sync.Map // map[int32]net.Conn
	relayConnID       atomic.Int32
	relayListener     net.Listener
	relayMutex        sync.Mutex
)

// StartRelayListener starts a TLS listener on the given address and notifies
// the proxy of each downstream agent connection via the control stream.
func StartRelayListener(listenAddr string, controlConn net.Conn) error {
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
		for {
			conn, err := lis.Accept()
			if err != nil {
				logrus.Debugf("Relay listener closed: %v", err)
				return
			}

			connID := relayConnID.Add(1)
			relayPendingConns.Store(connID, conn)

			logrus.Infof("Relay: downstream agent connected from %s (ID: %d)", conn.RemoteAddr(), connID)

			// Notify proxy via control stream
			if err := encoder.Encode(protocol.RelayNewConnectionPacket{
				ConnectionID: connID,
				RemoteAddr:   conn.RemoteAddr().String(),
			}); err != nil {
				logrus.Errorf("Relay: could not notify proxy of new connection: %v", err)
				conn.Close()
				relayPendingConns.Delete(connID)
				return
			}
		}
	}()

	return nil
}

// HandleRelayBridge bridges a yamux stream from the proxy to a pending downstream connection.
func HandleRelayBridge(bridgeConn net.Conn, connectionID int32) {
	val, ok := relayPendingConns.LoadAndDelete(connectionID)
	if !ok {
		logrus.Errorf("Relay bridge: no pending connection with ID %d", connectionID)
		return
	}

	downstreamConn := val.(net.Conn)
	logrus.Infof("Relay bridge: bridging connection ID %d to proxy", connectionID)

	// Bidirectional relay between downstream agent and proxy yamux stream
	relay.StartRelay(downstreamConn, bridgeConn)
}

// StopRelayListener stops the relay listener if one is active.
func StopRelayListener() {
	relayMutex.Lock()
	defer relayMutex.Unlock()
	if relayListener != nil {
		relayListener.Close()
		relayListener = nil
		logrus.Info("Relay listener stopped")
	}
}
