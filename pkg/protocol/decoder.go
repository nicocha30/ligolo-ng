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

package protocol

import (
	"fmt"
	"github.com/shamaton/msgpack/v2"
	"io"
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
	case MessageAgentKillRequest:
		return &AgentKillRequestPacket{}, nil
	case MessageListenerSocketConnectionReady:
		return &ListenerSocketConnectionReady{}, nil
	default:
		return nil, fmt.Errorf("decode called for unknown payload type: %d", payloadType)
	}
}

// Decode read content from the reader and fill the Envelope
func (d *LigoloDecoder) Decode() error {
	var payloadType uint8
	err := msgpack.UnmarshalRead(d.reader, &payloadType)
	if err != nil {
		return err
	}
	p, err := interfaceFromPayloadType(payloadType)
	if err != nil {
		return err
	}

	if err := msgpack.UnmarshalRead(d.reader, p); err != nil {
		return err
	}
	d.Payload = p

	return nil
}
