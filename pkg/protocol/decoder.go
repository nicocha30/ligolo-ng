package protocol

import (
	"fmt"
	"io"

	"github.com/vmihailenco/msgpack/v5"
)

// LigoloDecoder is the struct containing the decoded Envelope and the reader
type LigoloDecoder struct {
	reader  io.Reader
	Payload interface{}
}

// NewDecoder decode Ligolo-ng packets
func NewDecoder(reader io.Reader) LigoloDecoder {
	return LigoloDecoder{reader: reader}
}

func interfaceFromPayloadType(payloadType uint8) (interface{}, error) {
	switch payloadType {
	case MessageInfoRequest:
		return &InfoRequestPacket{}, nil
	case MessageInfoReply:
		return &InfoReplyPacket{}, nil
	case MessageConnectRequest:
		return &ConnectRequestPacket{}, nil
	case MessageConnectResponse:
		return &ConnectResponsePacket{}, nil
	case MessageHostPingRequest:
		return &HostPingRequestPacket{}, nil
	case MessageHostPingResponse:
		return &HostPingResponsePacket{}, nil
	case MessageListenerRequest:
		return &ListenerRequestPacket{}, nil
	case MessageListenerResponse:
		return &ListenerResponsePacket{}, nil
	case MessageListenerBindRequest:
		return &ListenerBindPacket{}, nil
	case MessageListenerBindResponse:
		return &ListenerBindReponse{}, nil
	case MessageListenerSockRequest:
		return &ListenerSockRequestPacket{}, nil
	case MessageListenerSockResponse:
		return &ListenerSockResponsePacket{}, nil
	case MessageListenerCloseRequest:
		return &ListenerCloseRequestPacket{}, nil
	case MessageListenerCloseResponse:
		return &ListenerCloseResponsePacket{}, nil
	default:
		return nil, fmt.Errorf("decode called for unknown payload type: %d", payloadType)
	}
}

// Decode read content from the reader and fill the Envelope
func (d *LigoloDecoder) Decode() error {
	packer := msgpack.NewDecoder(d.reader)
	var payloadType uint8

	err := packer.Decode(&payloadType)
	if err != nil {
		return err
	}

	p, err := interfaceFromPayloadType(payloadType)
	if err != nil {
		return err
	}

	if err := packer.Decode(p); err != nil {
		return err
	}
	d.Payload = p

	return nil
}
