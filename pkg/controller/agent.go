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

package controller

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/allsmog/ligolo-ng-relay/pkg/protocol"
	"github.com/allsmog/ligolo-ng-relay/pkg/proxy"
	"github.com/hashicorp/yamux"
	"github.com/sirupsen/logrus"
)

type LigoloAgent struct {
	mu                    sync.Mutex
	Name                  string
	Network               []protocol.NetInterface
	Session               *yamux.Session
	SessionID             string
	CloseChan             chan bool `json:"-"`
	Interface             string
	Running               bool
	Listeners             []*proxy.LigoloListener
	RelayCapable          bool
	RelayActive           bool
	RelayListenAddr       string
	RelayAuthToken        string `json:"-"`
	RelayTokenExpiresAt   time.Time
	RelayOneTimeToken     bool
	RelayOneTimeTokenUsed bool
	RelayCertFingerprint  string
	RelayLastError        string
	RelayLastErrorAt      time.Time
	RelayEvents           []RelayEvent
	RelayControl          net.Conn `json:"-"`
	ParentAgentID         string   // SessionID of the relay agent (empty if direct)
}

const (
	DefaultRelayTokenTTL = 8 * time.Hour
	maxRelayEvents       = 20
)

type RelayEvent struct {
	At         time.Time `json:"at"`
	Kind       string    `json:"kind"`
	RemoteAddr string    `json:"remote_addr,omitempty"`
	Message    string    `json:"message"`
}

type RelayStartOptions struct {
	ListenAddr     string
	AuthToken      string
	TokenTTL       time.Duration
	TokenExpiresAt time.Time
	OneTimeToken   bool
}

type RelayStartResult struct {
	CertFingerprint string    `json:"fingerprint"`
	AuthToken       string    `json:"auth_token"`
	TokenExpiresAt  time.Time `json:"token_expires_at"`
	OneTimeToken    bool      `json:"one_time_token"`
}

type RelayStatus struct {
	Active           bool         `json:"active"`
	ListenAddr       string       `json:"listen_addr,omitempty"`
	CertFingerprint  string       `json:"fingerprint,omitempty"`
	TokenExpiresAt   *time.Time   `json:"token_expires_at,omitempty"`
	TokenExpired     bool         `json:"token_expired"`
	OneTimeToken     bool         `json:"one_time_token"`
	OneTimeTokenUsed bool         `json:"one_time_token_used"`
	LastError        string       `json:"last_error,omitempty"`
	LastErrorAt      *time.Time   `json:"last_error_at,omitempty"`
	RecentEvents     []RelayEvent `json:"recent_events,omitempty"`
}

func (la *LigoloAgent) Alive() bool {
	if la.Session != nil && !la.Session.IsClosed() {
		return true
	}
	return false
}

func (la *LigoloAgent) ProbePathRTT(timeout time.Duration) (time.Duration, error) {
	if la.Session == nil || la.Session.IsClosed() {
		return 0, fmt.Errorf("agent is offline")
	}
	conn, err := la.Session.Open()
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	if timeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(timeout))
	}

	encoder := protocol.NewEncoder(conn)
	decoder := protocol.NewDecoder(conn)
	start := time.Now()
	if err := encoder.Encode(protocol.InfoRequestPacket{}); err != nil {
		return 0, err
	}
	if err := decoder.Decode(); err != nil {
		return 0, err
	}
	if _, ok := decoder.Payload.(*protocol.InfoReplyPacket); !ok {
		return 0, fmt.Errorf("unexpected health probe response")
	}
	return time.Since(start), nil
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

func (la *LigoloAgent) UpdateReconnectTarget(connectAddr, acceptFingerprint, relayToken string) error {
	if la.Session == nil || la.Session.IsClosed() {
		return fmt.Errorf("agent session is not connected")
	}
	conn, err := la.Session.Open()
	if err != nil {
		return err
	}
	defer conn.Close()

	ligoloProtocol := protocol.NewEncoderDecoder(conn)
	if err := ligoloProtocol.Encode(protocol.AgentReconnectRequestPacket{
		ConnectAddr:       connectAddr,
		AcceptFingerprint: acceptFingerprint,
		RelayToken:        relayToken,
	}); err != nil {
		return err
	}
	if err := ligoloProtocol.Decode(); err != nil {
		return err
	}
	response, ok := ligoloProtocol.Payload.(*protocol.AgentReconnectResponsePacket)
	if !ok {
		return fmt.Errorf("unexpected reconnect response type")
	}
	if response.Err {
		return fmt.Errorf("agent reconnect error: %s", response.ErrString)
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

func GenerateRelayAuthToken() (string, error) {
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(token), nil
}

func relayAuthTokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return fmt.Sprintf("%x", sum[:])
}

func (la *LigoloAgent) RecordRelayEvent(kind, remoteAddr, message string) {
	la.mu.Lock()
	defer la.mu.Unlock()

	event := RelayEvent{
		At:         time.Now(),
		Kind:       kind,
		RemoteAddr: remoteAddr,
		Message:    message,
	}
	la.RelayEvents = append(la.RelayEvents, event)
	if len(la.RelayEvents) > maxRelayEvents {
		la.RelayEvents = append([]RelayEvent(nil), la.RelayEvents[len(la.RelayEvents)-maxRelayEvents:]...)
	}
	switch kind {
	case "relay_start_failed", "relay_control_closed", "auth_rejected", "auth_overloaded", "pending_overloaded", "max_depth_rejected", "circular_chain_rejected", "bridge_failed", "register_failed":
		la.RelayLastError = message
		la.RelayLastErrorAt = event.At
	}
	if kind == "downstream_authenticated" && la.RelayOneTimeToken {
		la.RelayOneTimeTokenUsed = true
	}
}

func (la *LigoloAgent) RelayStatusSnapshot() RelayStatus {
	la.mu.Lock()
	defer la.mu.Unlock()

	var expiresAt *time.Time
	if !la.RelayTokenExpiresAt.IsZero() {
		value := la.RelayTokenExpiresAt
		expiresAt = &value
	}
	var lastErrorAt *time.Time
	if !la.RelayLastErrorAt.IsZero() {
		value := la.RelayLastErrorAt
		lastErrorAt = &value
	}
	events := append([]RelayEvent(nil), la.RelayEvents...)
	return RelayStatus{
		Active:           la.RelayActive,
		ListenAddr:       la.RelayListenAddr,
		CertFingerprint:  la.RelayCertFingerprint,
		TokenExpiresAt:   expiresAt,
		TokenExpired:     expiresAt != nil && !time.Now().Before(*expiresAt),
		OneTimeToken:     la.RelayOneTimeToken,
		OneTimeTokenUsed: la.RelayOneTimeTokenUsed,
		LastError:        la.RelayLastError,
		LastErrorAt:      lastErrorAt,
		RecentEvents:     events,
	}
}

// StartRelay activates relay mode on this agent, instructing it to listen for
// downstream agents on the given address. Returns the TLS certificate fingerprint
// and the downstream auth token that agents must present.
func (la *LigoloAgent) StartRelayWithOptions(options RelayStartOptions) (*RelayStartResult, error) {
	if la.RelayActive {
		return nil, fmt.Errorf("relay already active on %s", la.RelayListenAddr)
	}
	if !la.RelayCapable {
		return nil, fmt.Errorf("agent %s does not support relay mode", la.Name)
	}
	listenAddr := options.ListenAddr
	authToken := options.AuthToken
	if authToken == "" {
		var err error
		authToken, err = GenerateRelayAuthToken()
		if err != nil {
			return nil, fmt.Errorf("could not generate relay auth token: %v", err)
		}
	}
	tokenExpiresAt := options.TokenExpiresAt
	if tokenExpiresAt.IsZero() {
		tokenTTL := options.TokenTTL
		if tokenTTL <= 0 {
			tokenTTL = DefaultRelayTokenTTL
		}
		tokenExpiresAt = time.Now().Add(tokenTTL)
	}
	if !tokenExpiresAt.After(time.Now()) {
		return nil, fmt.Errorf("relay auth token expiry must be in the future")
	}

	// Open a yamux stream to the agent for the relay control channel
	controlStream, err := la.Session.Open()
	if err != nil {
		la.RecordRelayEvent("relay_start_failed", "", fmt.Sprintf("could not open relay control stream: %v", err))
		return nil, fmt.Errorf("could not open relay control stream: %v", err)
	}

	encoder := protocol.NewEncoder(controlStream)
	decoder := protocol.NewDecoder(controlStream)

	// Send relay request
	if err := encoder.Encode(protocol.RelayRequestPacket{
		ListenAddr:             listenAddr,
		AuthTokenHash:          relayAuthTokenHash(authToken),
		AuthTokenExpiresAtUnix: tokenExpiresAt.Unix(),
		OneTimeToken:           options.OneTimeToken,
	}); err != nil {
		controlStream.Close()
		la.RecordRelayEvent("relay_start_failed", "", fmt.Sprintf("could not send relay request: %v", err))
		return nil, fmt.Errorf("could not send relay request: %v", err)
	}

	// Read response
	if err := decoder.Decode(); err != nil {
		controlStream.Close()
		la.RecordRelayEvent("relay_start_failed", "", fmt.Sprintf("could not read relay response: %v", err))
		return nil, fmt.Errorf("could not read relay response: %v", err)
	}

	resp, ok := decoder.Payload.(*protocol.RelayResponsePacket)
	if !ok {
		controlStream.Close()
		la.RecordRelayEvent("relay_start_failed", "", "unexpected relay response type")
		return nil, fmt.Errorf("unexpected response type")
	}
	if resp.Err {
		controlStream.Close()
		la.RecordRelayEvent("relay_start_failed", "", resp.ErrString)
		return nil, fmt.Errorf("agent relay error: %s", resp.ErrString)
	}

	la.RelayActive = true
	la.RelayListenAddr = listenAddr
	la.RelayAuthToken = authToken
	la.RelayTokenExpiresAt = tokenExpiresAt
	la.RelayOneTimeToken = options.OneTimeToken
	la.RelayOneTimeTokenUsed = false
	la.RelayCertFingerprint = resp.CertFingerprint
	la.RelayLastError = ""
	la.RelayLastErrorAt = time.Time{}
	la.RelayControl = controlStream
	la.RecordRelayEvent("relay_started", "", fmt.Sprintf("relay listening on %s", listenAddr))

	return &RelayStartResult{
		CertFingerprint: resp.CertFingerprint,
		AuthToken:       authToken,
		TokenExpiresAt:  tokenExpiresAt,
		OneTimeToken:    options.OneTimeToken,
	}, nil
}

func (la *LigoloAgent) StartRelay(listenAddr string, authToken string) (string, string, error) {
	result, err := la.StartRelayWithOptions(RelayStartOptions{
		ListenAddr: listenAddr,
		AuthToken:  authToken,
	})
	if err != nil {
		return "", "", err
	}
	return result.CertFingerprint, result.AuthToken, nil
}

// StopRelay deactivates relay mode by closing the control stream.
func (la *LigoloAgent) StopRelay() error {
	if !la.RelayActive {
		return fmt.Errorf("relay is not active")
	}
	control := la.RelayControl
	la.RelayActive = false
	la.RelayListenAddr = ""
	la.RelayAuthToken = ""
	la.RelayTokenExpiresAt = time.Time{}
	la.RelayOneTimeToken = false
	la.RelayOneTimeTokenUsed = false
	la.RelayCertFingerprint = ""
	la.RelayControl = nil
	if control != nil {
		control.Close()
	}
	la.RecordRelayEvent("relay_stopped", "", "relay stopped")
	return nil
}

// HandleRelayNotifications listens on the relay control stream for downstream
// agent connection notifications and bridges them back to the proxy.
// registerFunc is called with each newly registered downstream agent.
func (la *LigoloAgent) HandleRelayNotifications(chainMgr *proxy.ChainManager, registerFunc func(*LigoloAgent) error) {
	decoder := protocol.NewDecoder(la.RelayControl)

	for {
		if err := decoder.Decode(); err != nil {
			wasActive := la.RelayActive
			// Control stream closed — relay stopped
			la.RelayActive = false
			la.RelayListenAddr = ""
			la.RelayAuthToken = ""
			la.RelayTokenExpiresAt = time.Time{}
			la.RelayOneTimeToken = false
			la.RelayOneTimeTokenUsed = false
			la.RelayCertFingerprint = ""
			la.RelayControl = nil
			if wasActive {
				la.RecordRelayEvent("relay_control_closed", "", fmt.Sprintf("relay control channel closed: %v", err))
			}
			return
		}

		switch payload := decoder.Payload.(type) {
		case *protocol.RelayEventPacket:
			if payload.AtUnix > 0 {
				la.recordRelayEventAt(time.Unix(payload.AtUnix, 0), payload.Kind, payload.RemoteAddr, payload.Message)
			} else {
				la.RecordRelayEvent(payload.Kind, payload.RemoteAddr, payload.Message)
			}
			continue
		case *protocol.RelayNewConnectionPacket:
			la.handleRelayNewConnection(chainMgr, registerFunc, payload)
		default:
			la.RecordRelayEvent("unexpected_relay_packet", "", fmt.Sprintf("unexpected relay packet type %T", decoder.Payload))
		}
	}
}

func (la *LigoloAgent) recordRelayEventAt(at time.Time, kind, remoteAddr, message string) {
	la.mu.Lock()
	defer la.mu.Unlock()

	event := RelayEvent{
		At:         at,
		Kind:       kind,
		RemoteAddr: remoteAddr,
		Message:    message,
	}
	la.RelayEvents = append(la.RelayEvents, event)
	if len(la.RelayEvents) > maxRelayEvents {
		la.RelayEvents = append([]RelayEvent(nil), la.RelayEvents[len(la.RelayEvents)-maxRelayEvents:]...)
	}
	switch kind {
	case "relay_start_failed", "relay_control_closed", "auth_rejected", "auth_overloaded", "pending_overloaded", "max_depth_rejected", "circular_chain_rejected", "bridge_failed", "register_failed":
		la.RelayLastError = message
		la.RelayLastErrorAt = event.At
	}
	if kind == "downstream_authenticated" && la.RelayOneTimeToken {
		la.RelayOneTimeTokenUsed = true
	}
}

func (la *LigoloAgent) handleRelayNewConnection(chainMgr *proxy.ChainManager, registerFunc func(*LigoloAgent) error, notification *protocol.RelayNewConnectionPacket) {
	// Check depth limit
	if chainMgr.WouldExceedMaxDepth(la.SessionID) {
		message := fmt.Sprintf("maximum chain depth reached for downstream agent from %s", notification.RemoteAddr)
		logrus.Warnf("Relay: %s", message)
		la.RecordRelayEvent("max_depth_rejected", notification.RemoteAddr, message)
		la.closeRelayPendingConnection(notification.ConnectionID)
		return
	}

	// Open a new yamux stream to the relay agent for bridging
	bridgeStream, err := la.Session.Open()
	if err != nil {
		message := fmt.Sprintf("could not open bridge stream: %v", err)
		la.RecordRelayEvent("bridge_failed", notification.RemoteAddr, message)
		logrus.Errorf("Relay: %s", message)
		la.closeRelayPendingConnection(notification.ConnectionID)
		return
	}

	// Send bridge request
	encoder := protocol.NewEncoder(bridgeStream)
	if err := encoder.Encode(protocol.RelayBridgeRequestPacket{
		ConnectionID: notification.ConnectionID,
	}); err != nil {
		bridgeStream.Close()
		message := fmt.Sprintf("could not send bridge request: %v", err)
		la.RecordRelayEvent("bridge_failed", notification.RemoteAddr, message)
		logrus.Errorf("Relay: %s", message)
		la.closeRelayPendingConnection(notification.ConnectionID)
		return
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
		message := fmt.Sprintf("could not create yamux session for downstream agent: %v", err)
		la.RecordRelayEvent("bridge_failed", notification.RemoteAddr, message)
		logrus.Errorf("Relay: %s", message)
		return
	}

	// Register the downstream agent using the normal flow
	downstreamAgent, err := NewAgent(downstreamSession)
	if err != nil {
		downstreamSession.Close()
		message := fmt.Sprintf("could not register downstream agent: %v", err)
		la.RecordRelayEvent("register_failed", notification.RemoteAddr, message)
		logrus.Errorf("Relay: %s", message)
		return
	}

	// Check for circular chains
	if chainMgr.IsCircular(la.SessionID, downstreamAgent.SessionID) {
		downstreamSession.Close()
		message := fmt.Sprintf("circular chain detected, rejecting agent %s", downstreamAgent.SessionID)
		la.RecordRelayEvent("circular_chain_rejected", notification.RemoteAddr, message)
		logrus.Warnf("Relay: %s", message)
		return
	}

	downstreamAgent.ParentAgentID = la.SessionID
	chainMgr.AddLink(la.SessionID, downstreamAgent.SessionID)

	logrus.Infof("Downstream agent joined via %s: %s (%s)", la.Name, downstreamAgent.Name, notification.RemoteAddr)
	la.RecordRelayEvent("downstream_registered", notification.RemoteAddr, fmt.Sprintf("downstream agent registered: %s", downstreamAgent.Name))

	if err := registerFunc(downstreamAgent); err != nil {
		message := fmt.Sprintf("could not register downstream agent: %v", err)
		la.RecordRelayEvent("register_failed", notification.RemoteAddr, message)
		logrus.Errorf("Relay: %s", message)
		downstreamSession.Close()
		chainMgr.RemoveAgent(downstreamAgent.SessionID)
		return
	}

	go func(a *LigoloAgent) {
		<-a.Session.CloseChan()
		chainMgr.RemoveAgent(a.SessionID)
		message := fmt.Sprintf("downstream agent dropped: %s", a.Name)
		la.RecordRelayEvent("downstream_dropped", "", message)
		logrus.WithFields(logrus.Fields{
			"name":    a.Name,
			"session": a.SessionID,
			"via":     la.Name,
		}).Warn("Downstream agent dropped")
	}(downstreamAgent)
}

func (la *LigoloAgent) closeRelayPendingConnection(connectionID int32) {
	if la.Session == nil || la.Session.IsClosed() {
		return
	}
	bridgeStream, err := la.Session.Open()
	if err != nil {
		logrus.Debugf("Relay: could not open reject stream for connection ID %d: %v", connectionID, err)
		return
	}
	defer bridgeStream.Close()
	encoder := protocol.NewEncoder(bridgeStream)
	if err := encoder.Encode(protocol.RelayBridgeRequestPacket{ConnectionID: connectionID}); err != nil {
		logrus.Debugf("Relay: could not reject pending connection ID %d: %v", connectionID, err)
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
