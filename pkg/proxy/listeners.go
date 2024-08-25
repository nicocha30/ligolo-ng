package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/hashicorp/yamux"
	"github.com/nicocha30/ligolo-ng/pkg/protocol"
	"github.com/nicocha30/ligolo-ng/pkg/relay"
	"github.com/sirupsen/logrus"
)

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
	if err := ligoloProtocol.Encode(listenerPacket); err != nil {
		return LigoloListener{}, err
	}

	// Get response from agent
	if err := ligoloProtocol.Decode(); err != nil {
		return LigoloListener{}, err
	}
	response := ligoloProtocol.Payload.(*protocol.ListenerResponsePacket)
	if err := response.Err; err {
		return LigoloListener{}, errors.New(response.ErrString)
	}
	return LigoloListener{ID: response.ListenerID, sess: sess, Conn: conn, addr: addr, network: network, to: to}, nil
}

func (l *LigoloListener) ResetMultiplexer(sess *yamux.Session) error {
	// Change the listener session, used in session recovery mechanism
	l.sess = sess
	conn, err := sess.Open()
	if err != nil {
		return err
	}
	l.Conn = conn
	return nil
}

func (l *LigoloListener) RedirectAddr() string {
	return l.to
}

func (l *LigoloListener) ListenerAddr() string {
	return l.addr
}

func (l *LigoloListener) Network() string {
	return l.network
}

func (l *LigoloListener) String() string {
	return fmt.Sprintf("[#%d] (%s) [Agent] %s => [Proxy] %s", l.ID, l.network, l.addr, l.to)
}

func (l *LigoloListener) Stop() error {
	// Open Yamux connection
	yamuxConnectionSession, err := l.sess.Open()
	if err != nil {
		return err
	}

	ligoloProtocol := protocol.NewEncoderDecoder(yamuxConnectionSession)

	// Send close request
	closeRequest := protocol.ListenerCloseRequestPacket{ListenerID: l.ID}
	if err := ligoloProtocol.Encode(closeRequest); err != nil {
		return err
	}

	// Process close response
	if err := ligoloProtocol.Decode(); err != nil {
		return err

	}

	if err := ligoloProtocol.Payload.(*protocol.ListenerCloseResponsePacket).Err; err != false {
		return errors.New(ligoloProtocol.Payload.(*protocol.ListenerCloseResponsePacket).ErrString)
	}
	return nil
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
				logrus.Debug("Listener closed connection (EOF)")
				return nil
			}
			return err
		}

		// We received a new BindResponse!
		response := ligoloProtocol.Payload.(*protocol.ListenerBindReponse)

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
			if err := forwarderProtocolEncDec.Encode(socketRequestPacket); err != nil {
				logrus.Error(err)
				return
			}
			if err := forwarderProtocolEncDec.Decode(); err != nil {
				logrus.Error(err)
				return
			}

			if err := forwarderProtocolEncDec.Payload.(*protocol.ListenerSockResponsePacket).Err; err != false {
				logrus.Error(forwarderProtocolEncDec.Payload.(*protocol.ListenerSockResponsePacket).ErrString)
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
