package controller

import (
	"fmt"

	"github.com/hashicorp/yamux"
	"github.com/nicocha30/ligolo-ng/pkg/protocol"
	"github.com/nicocha30/ligolo-ng/pkg/proxy"
)

type LigoloAgent struct {
	Name      string
	Network   []protocol.NetInterface
	Session   *yamux.Session
	SessionID string
	CloseChan chan bool
	Interface string
	Running   bool
	Listeners []*proxy.LigoloListener
}

func (la *LigoloAgent) AddListener(addr string, network string, to string) (*proxy.LigoloListener, error) {
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

func (la *LigoloAgent) String() string {
	raddr := "[Offline]"
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

	if err := protocolEncoder.Encode(infoRequest); err != nil {
		return nil, err
	}

	if err := protocolDecoder.Decode(); err != nil {
		return nil, err
	}

	reply := protocolDecoder.Payload.(*protocol.InfoReplyPacket)

	return &LigoloAgent{
		Name:      reply.Name,
		Network:   reply.Interfaces,
		Session:   session,
		SessionID: reply.SessionID,
		CloseChan: make(chan bool),
	}, nil
}
