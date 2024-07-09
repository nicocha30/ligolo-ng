package controller

import (
	"fmt"
	"github.com/hashicorp/yamux"
	"github.com/nicocha30/ligolo-ng/pkg/protocol"
	"net"
)

var ListenerCounter = 0

type LigoloAgent struct {
	Name      string
	Network   []protocol.NetInterface
	Session   *yamux.Session
	SessionID string
	CloseChan chan bool
	Interface string
	Running   bool
}

type Listener struct {
	Agent        LigoloAgent
	Network      string
	ListenerAddr string
	RedirectAddr string

	Session    net.Conn
	ListenerID int32
}

func (l Listener) String() string {
	return fmt.Sprintf("[%s] (%s) [Agent] %s => [Proxy] %s", l.Agent.Name, l.Network, l.ListenerAddr, l.RedirectAddr)
}

func (la *LigoloAgent) String() string {
	raddr := "Disconnected"
	if la.Session != nil {
		raddr = la.Session.RemoteAddr().String()
	}

	return fmt.Sprintf("%s - %s - %s", la.Name, raddr, la.SessionID)
}

func NewAgent(session *yamux.Session) (*LigoloAgent, error) {
	yamuxConnectionSession, err := session.Open()
	if err != nil {
		return nil, err
	}

	infoRequest := protocol.InfoRequestPacket{}

	protocolEncoder := protocol.NewEncoder(yamuxConnectionSession)
	protocolDecoder := protocol.NewDecoder(yamuxConnectionSession)

	if err := protocolEncoder.Encode(protocol.Envelope{
		Type:    protocol.MessageInfoRequest,
		Payload: infoRequest,
	}); err != nil {
		return nil, err
	}

	if err := protocolDecoder.Decode(); err != nil {
		return nil, err
	}

	response := protocolDecoder.Envelope.Payload
	reply := response.(protocol.InfoReplyPacket)

	return &LigoloAgent{
		Name:      reply.Name,
		Network:   reply.Interfaces,
		Session:   session,
		SessionID: reply.SessionID,
		CloseChan: make(chan bool),
	}, nil
}
