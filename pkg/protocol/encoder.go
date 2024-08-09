package protocol

import (
	"fmt"
	"io"

	"github.com/vmihailenco/msgpack/v5"
)

// LigoloEncoder is the structure containing the writer used when encoding Envelopes
type LigoloEncoder struct {
	writer io.Writer
}

// NewEncoder encode Ligolo-ng packets
func NewEncoder(writer io.Writer) LigoloEncoder {
	return LigoloEncoder{writer: writer}
}

func payloadTypeFromInterface(payload interface{}) (uint8, error) {
	switch payload := payload.(type) {
	case InfoRequestPacket:
		return MessageInfoRequest, nil
	case InfoReplyPacket:
		return MessageInfoReply, nil
	case ConnectRequestPacket:
		return MessageConnectRequest, nil
	case ConnectResponsePacket:
		return MessageConnectResponse, nil
	case HostPingRequestPacket:
		return MessageHostPingRequest, nil
	case HostPingResponsePacket:
		return MessageHostPingResponse, nil
	case ListenerRequestPacket:
		return MessageListenerRequest, nil
	case ListenerResponsePacket:
		return MessageListenerResponse, nil
	case ListenerBindPacket:
		return MessageListenerBindRequest, nil
	case ListenerBindReponse:
		return MessageListenerBindResponse, nil
	case ListenerSockRequestPacket:
		return MessageListenerSockRequest, nil
	case ListenerSockResponsePacket:
		return MessageListenerSockResponse, nil
	case ListenerCloseRequestPacket:
		return MessageListenerCloseRequest, nil
	case ListenerCloseResponsePacket:
		return MessageListenerCloseResponse, nil
	default:
		return 0, fmt.Errorf("payloadTypeFromInterface called for unknown payload type: %v", payload)
	}
}

// Encode an Envelope packet and write the result into the writer
func (e *LigoloEncoder) Encode(payload interface{}) error {
	packer := msgpack.NewEncoder(e.writer)

	payloadType, err := payloadTypeFromInterface(payload)
	if err != nil {
		return err
	}

	if err := packer.Encode(payloadType); err != nil {
		return err
	}

	if err := packer.Encode(payload); err != nil {
		return err
	}

	return nil
}
