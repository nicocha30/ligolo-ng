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

package controller

import (
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/hashicorp/yamux"
	"github.com/nicocha30/ligolo-ng/pkg/protocol"
	"github.com/nicocha30/ligolo-ng/pkg/proxy"
)

type LigoloAgent struct {
	Name            string
	Network         []protocol.NetInterface
	Session         *yamux.Session
	SessionID       string
	CloseChan       chan bool `json:"-"`
	Interface       string
	Running         bool
	Listeners       []*proxy.LigoloListener
	RelayCapable    bool
	RelayActive     bool
	RelayListenAddr string
	RelayControl    net.Conn `json:"-"`
	ParentAgentID   string   // SessionID of the relay agent (empty if direct)
}

func (la *LigoloAgent) Alive() bool {
	if la.Session != nil && !la.Session.IsClosed() {
		return true
	}
	return false
}

func (la *LigoloAgent) Kill() error {
	// Open a new Yamux Session
	conn, err := la.Session.Open()
	if err != nil {
		return err
	}
	defer conn.Close()

	ligoloProtocol := protocol.NewEncoderDecoder(conn)

	// Request to kill the agent
	if err := ligoloProtocol.Encode(protocol.AgentKillRequestPacket{}); err != nil {
		return err
	}
	return nil
}

func (la *LigoloAgent) AddListener(addr string, network string, to string) (*proxy.LigoloListener, error) {
	if _, _, err := net.SplitHostPort(addr); err != nil {
		return nil, fmt.Errorf("invalid listener addr: %v", err)
	}
	if _, _, err := net.SplitHostPort(to); err != nil {
		return nil, fmt.Errorf("invalid redirect addr: %v", err)
	}
	proxyListener, err := proxy.NewListener(la.Session, addr, network, to)
	if err != nil {
		return nil, err
	}
	la.Listeners = append(la.Listeners, &proxyListener)
	return &proxyListener, nil
}

func (la *LigoloAgent) GetListener(id int) *proxy.LigoloListener {
	for _, listener := range la.Listeners {
		if listener.ID == int32(id) {
			return listener
		}
	}
	return nil
}

func (la *LigoloAgent) DeleteListener(id int) {
	for i, listener := range la.Listeners {
		if listener.ID == int32(id) {
			la.Listeners = append(la.Listeners[:i], la.Listeners[i+1:]...)
		}
	}
}

// StartRelay activates relay mode on this agent, instructing it to listen for
// downstream agents on the given address. Returns the TLS certificate fingerprint.
func (la *LigoloAgent) StartRelay(listenAddr string) (string, error) {
	if la.RelayActive {
		return "", fmt.Errorf("relay already active on %s", la.RelayListenAddr)
	}
	if !la.RelayCapable {
		return "", fmt.Errorf("agent %s does not support relay mode", la.Name)
	}

	// Open a yamux stream to the agent for the relay control channel
	controlStream, err := la.Session.Open()
	if err != nil {
		return "", fmt.Errorf("could not open relay control stream: %v", err)
	}

	encoder := protocol.NewEncoder(controlStream)
	decoder := protocol.NewDecoder(controlStream)

	// Send relay request
	if err := encoder.Encode(protocol.RelayRequestPacket{
		ListenAddr: listenAddr,
	}); err != nil {
		controlStream.Close()
		return "", fmt.Errorf("could not send relay request: %v", err)
	}

	// Read response
	if err := decoder.Decode(); err != nil {
		controlStream.Close()
		return "", fmt.Errorf("could not read relay response: %v", err)
	}

	resp, ok := decoder.Payload.(*protocol.RelayResponsePacket)
	if !ok {
		controlStream.Close()
		return "", fmt.Errorf("unexpected response type")
	}
	if resp.Err {
		controlStream.Close()
		return "", fmt.Errorf("agent relay error: %s", resp.ErrString)
	}

	la.RelayActive = true
	la.RelayListenAddr = listenAddr
	la.RelayControl = controlStream

	return resp.CertFingerprint, nil
}

// StopRelay deactivates relay mode by closing the control stream.
func (la *LigoloAgent) StopRelay() error {
	if !la.RelayActive {
		return fmt.Errorf("relay is not active")
	}
	if la.RelayControl != nil {
		la.RelayControl.Close()
	}
	la.RelayActive = false
	la.RelayListenAddr = ""
	la.RelayControl = nil
	return nil
}

// HandleRelayNotifications listens on the relay control stream for downstream
// agent connection notifications and bridges them back to the proxy.
// registerFunc is called with each newly registered downstream agent.
func (la *LigoloAgent) HandleRelayNotifications(chainMgr *proxy.ChainManager, registerFunc func(*LigoloAgent) error) {
	decoder := protocol.NewDecoder(la.RelayControl)

	for {
		if err := decoder.Decode(); err != nil {
			// Control stream closed — relay stopped
			la.RelayActive = false
			la.RelayListenAddr = ""
			la.RelayControl = nil
			return
		}

		notification, ok := decoder.Payload.(*protocol.RelayNewConnectionPacket)
		if !ok {
			continue
		}

		// Check depth limit
		if chainMgr.WouldExceedMaxDepth(la.SessionID) {
			fmt.Printf("WARNING: Maximum chain depth reached, rejecting downstream agent from %s\n", notification.RemoteAddr)
			continue
		}

		// Open a new yamux stream to the relay agent for bridging
		bridgeStream, err := la.Session.Open()
		if err != nil {
			fmt.Printf("ERROR: Could not open bridge stream: %v\n", err)
			continue
		}

		// Send bridge request
		encoder := protocol.NewEncoder(bridgeStream)
		if err := encoder.Encode(protocol.RelayBridgeRequestPacket{
			ConnectionID: notification.ConnectionID,
		}); err != nil {
			bridgeStream.Close()
			fmt.Printf("ERROR: Could not send bridge request: %v\n", err)
			continue
		}

		// The bridge stream is now connected to the downstream agent's raw TLS connection.
		// Create a yamux Client session over it to talk to the downstream agent.
		yamuxConfig := yamux.DefaultConfig()
		yamuxConfig.EnableKeepAlive = true
		yamuxConfig.KeepAliveInterval = 60 * time.Second
		yamuxConfig.ConnectionWriteTimeout = 120 * time.Second
		yamuxConfig.MaxStreamWindowSize = 16 * 1024 * 1024

		downstreamSession, err := yamux.Client(bridgeStream, yamuxConfig)
		if err != nil {
			bridgeStream.Close()
			fmt.Printf("ERROR: Could not create yamux session for downstream agent: %v\n", err)
			continue
		}

		// Register the downstream agent using the normal flow
		downstreamAgent, err := NewAgent(downstreamSession)
		if err != nil {
			downstreamSession.Close()
			fmt.Printf("ERROR: Could not register downstream agent: %v\n", err)
			continue
		}

		// Check for circular chains
		if chainMgr.IsCircular(la.SessionID, downstreamAgent.SessionID) {
			downstreamSession.Close()
			fmt.Printf("WARNING: Circular chain detected, rejecting agent %s\n", downstreamAgent.SessionID)
			continue
		}

		downstreamAgent.ParentAgentID = la.SessionID
		chainMgr.AddLink(la.SessionID, downstreamAgent.SessionID)

		fmt.Printf("INFO: Downstream agent joined via %s: %s (%s)\n", la.Name, downstreamAgent.Name, notification.RemoteAddr)

		if err := registerFunc(downstreamAgent); err != nil {
			fmt.Printf("ERROR: Could not register downstream agent: %v\n", err)
		}
	}
}

func (la *LigoloAgent) String() string {
	raddr := "[Offline]"
	if la.Session != nil {
		raddr = la.Session.RemoteAddr().String()
	}

	suffix := ""
	if la.ParentAgentID != "" {
		suffix = fmt.Sprintf(" (via %s)", la.ParentAgentID)
	}
	if la.RelayActive {
		suffix += " [relay]"
	}

	return fmt.Sprintf("%s - %s - %s%s", la.Name, raddr, la.SessionID, suffix)
}

func (la *LigoloAgent) MarshalJSON() ([]byte, error) {
	type Session struct {
		Name            string
		Network         []protocol.NetInterface
		SessionID       string
		RemoteAddr      string
		Interface       string
		Running         bool
		Listeners       []*proxy.LigoloListener
		RelayCapable    bool
		RelayActive     bool
		RelayListenAddr string
		ParentAgentID   string
	}

	return json.Marshal(Session{
		Name:            la.Name,
		Running:         la.Running,
		Listeners:       la.Listeners,
		Network:         la.Network,
		Interface:       la.Interface,
		SessionID:       la.SessionID,
		RemoteAddr:      la.Session.RemoteAddr().String(),
		RelayCapable:    la.RelayCapable,
		RelayActive:     la.RelayActive,
		RelayListenAddr: la.RelayListenAddr,
		ParentAgentID:   la.ParentAgentID,
	})
}

func NewAgent(session *yamux.Session) (*LigoloAgent, error) {
	yamuxConnectionSession, err := session.Open()
	if err != nil {
		return nil, fmt.Errorf("could not open yamux connection session: %v", err)
	}
	defer yamuxConnectionSession.Close()

	infoRequest := protocol.InfoRequestPacket{}

	protocolEncoder := protocol.NewEncoder(yamuxConnectionSession)
	protocolDecoder := protocol.NewDecoder(yamuxConnectionSession)

	if err := protocolEncoder.Encode(infoRequest); err != nil {
		return nil, fmt.Errorf("NewAgent: could not encode info request: %v", err)
	}

	if err := protocolDecoder.Decode(); err != nil {
		return nil, fmt.Errorf("NewAgent: could not decode info reply: %v", err)
	}

	reply := protocolDecoder.Payload.(*protocol.InfoReplyPacket)

	return &LigoloAgent{
		Name:         reply.Name,
		Network:      reply.Interfaces,
		Session:      session,
		SessionID:    reply.SessionID,
		CloseChan:    make(chan bool),
		RelayCapable: reply.RelayCapable,
	}, nil
}
