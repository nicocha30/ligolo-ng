package proxy

import (
	"context"
	"errors"
	"github.com/hashicorp/yamux"
	"github.com/nicocha30/ligolo-ng/pkg/protocol"
	"github.com/nicocha30/ligolo-ng/pkg/relay"
	"github.com/sirupsen/logrus"
	"io"
	"net"
)

func ListenerStop(sess *yamux.Session, listenerId int32) error {
	// Open Yamux connection
	yamuxConnectionSession, err := sess.Open()
	if err != nil {
		return err
	}

	ligoloProtocol := protocol.NewEncoderDecoder(yamuxConnectionSession)

	// Send close request
	closeRequest := protocol.ListenerCloseRequestPacket{ListenerID: listenerId}
	if err := ligoloProtocol.Encode(protocol.Envelope{
		Type:    protocol.MessageListenerCloseRequest,
		Payload: closeRequest,
	}); err != nil {
		return err
	}

	// Process close response
	if err := ligoloProtocol.Decode(); err != nil {
		return err

	}
	response := ligoloProtocol.Envelope.Payload

	if err := response.(protocol.ListenerCloseResponsePacket).Err; err != false {
		return errors.New(response.(protocol.ListenerCloseResponsePacket).ErrString)
	}
	return nil
}

type LigoloListener struct {
	ID      int32
	ctx     context.Context
	sess    *yamux.Session
	Conn    net.Conn
	addr    string
	network string
	to      string
}

func NewListener(sess *yamux.Session, addr string, network string, to string) (LigoloListener, error) {
	// Open a new Yamux Session
	conn, err := sess.Open()
	if err != nil {
		return LigoloListener{}, err
	}

	ligoloProtocol := protocol.NewEncoderDecoder(conn)

	// Request to open a new port on the agent
	listenerPacket := protocol.ListenerRequestPacket{Address: addr, Network: network}
	if err := ligoloProtocol.Encode(protocol.Envelope{
		Type:    protocol.MessageListenerRequest,
		Payload: listenerPacket,
	}); err != nil {
		return LigoloListener{}, err
	}

	// Get response from agent
	if err := ligoloProtocol.Decode(); err != nil {
		return LigoloListener{}, err
	}
	response := ligoloProtocol.Envelope.Payload.(protocol.ListenerResponsePacket)
	if err := response.Err; err != false {
		return LigoloListener{}, errors.New(response.ErrString)
	}
	return LigoloListener{ID: response.ListenerID, sess: sess, Conn: conn, addr: addr, network: network, to: to}, nil
}

func (l *LigoloListener) StartRelay() error {
	if l.network == "tcp" {
		return l.relayTCP()
	} else if l.network == "udp" {
		return l.relayUDP()
	}
	return errors.New("invalid network")
}

func (l *LigoloListener) relayTCP() error {
	ligoloProtocol := protocol.NewEncoderDecoder(l.Conn)
	for {
		// Wait for BindResponses
		if err := ligoloProtocol.Decode(); err != nil {
			if err == io.EOF {
				// Listener closed.
				return err
			}
			return err
		}

		// We received a new BindResponse!
		response := ligoloProtocol.Envelope.Payload.(protocol.ListenerBindReponse)

		if err := response.Err; err != false {
			return errors.New(response.ErrString)
		}

		logrus.Debugf("New socket opened : %d", response.SockID)

		// relay connection
		go func(sockID int32) {
			forwarderSession, err := l.sess.Open()
			if err != nil {
				logrus.Error(err)
				return
			}

			forwarderProtocolEncDec := protocol.NewEncoderDecoder(forwarderSession)

			// Request socket access
			socketRequestPacket := protocol.ListenerSockRequestPacket{SockID: sockID}
			if err := forwarderProtocolEncDec.Encode(protocol.Envelope{
				Type:    protocol.MessageListenerSockRequest,
				Payload: socketRequestPacket,
			}); err != nil {
				logrus.Error(err)
				return
			}
			if err := forwarderProtocolEncDec.Decode(); err != nil {
				logrus.Error(err)
				return
			}

			response := forwarderProtocolEncDec.Envelope.Payload
			if err := response.(protocol.ListenerSockResponsePacket).Err; err != false {
				logrus.Error(response.(protocol.ListenerSockResponsePacket).ErrString)
				return
			}
			// Got socket access!

			logrus.Debug("Listener relay established!")

			// Dial the "to" target
			lconn, err := net.Dial(l.network, l.to)
			if err != nil {
				logrus.Error(err)
				return
			}

			// relay connections
			if err := relay.StartRelay(lconn, forwarderSession); err != nil {
				logrus.Error(err)
				return
			}
		}(response.SockID)

	}

}

func (l *LigoloListener) relayUDP() error {
	// Dial the "to" target
	lconn, err := net.Dial(l.network, l.to)
	if err != nil {
		return err
	}
	// Relay conn
	err = relay.StartPacketRelay(lconn, l.Conn)
	if err != nil {
		return err
	}
	return nil
}
