package proxy

import (
	"fmt"
	"github.com/hashicorp/yamux"
	"ligolo-ng/pkg/protocol"
	"net"
)

var AgentCounter = 0
var ListenerCounter = 0

type LigoloAgent struct {
	Id        int
	Name      string
	Network   []protocol.NetInterface
	Session   *yamux.Session
	CloseChan chan bool
}

type Listener struct {
	Agent        LigoloAgent
	Network      string
	ListenerAddr string
	RedirectAddr string

	Session    net.Conn
	ListenerID int32
}

func (la *LigoloAgent) String() string {
	return fmt.Sprintf("%s - %s", la.Name, la.Session.RemoteAddr())
}

func NewAgent(session *yamux.Session) (LigoloAgent, error) {
	yamuxConnectionSession, err := session.Open()
	if err != nil {
		return LigoloAgent{}, err
	}

	infoRequest := protocol.InfoRequestPacket{}

	protocolEncoder := protocol.NewEncoder(yamuxConnectionSession)
	protocolDecoder := protocol.NewDecoder(yamuxConnectionSession)

	if err := protocolEncoder.Encode(protocol.Envelope{
		Type:    protocol.MessageInfoRequest,
		Payload: infoRequest,
	}); err != nil {
		return LigoloAgent{}, err
	}

	if err := protocolDecoder.Decode(); err != nil {
		return LigoloAgent{}, err
	}

	response := protocolDecoder.Envelope.Payload
	reply := response.(protocol.InfoReplyPacket)
	AgentCounter++
	return LigoloAgent{
		Id:        AgentCounter,
		Name:      reply.Name,
		Network:   reply.Interfaces,
		Session:   session,
		CloseChan: make(chan bool),
	}, nil
}
