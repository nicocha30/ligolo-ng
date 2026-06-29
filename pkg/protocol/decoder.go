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

package protocol

import (
	"errors"
	"fmt"
	"io"

	"github.com/vmihailenco/msgpack/v5"
)

const maxProtocolPacketBytes int64 = 1 << 20

var errProtocolPacketTooLarge = errors.New("protocol packet exceeds maximum control-plane size")

type protocolLimitReader struct {
	reader     io.Reader
	remaining  int64
	lastByte   byte
	canUnread  bool
	unreadByte bool
}

func newProtocolLimitReader(reader io.Reader) *protocolLimitReader {
	return &protocolLimitReader{reader: reader, remaining: maxProtocolPacketBytes}
}

func (r *protocolLimitReader) Reset() {
	r.remaining = maxProtocolPacketBytes
	r.canUnread = false
}

func (r *protocolLimitReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if r.unreadByte {
		if r.remaining <= 0 {
			return 0, errProtocolPacketTooLarge
		}
		p[0] = r.lastByte
		r.unreadByte = false
		r.remaining--
		r.canUnread = false
		return 1, nil
	}
	if r.remaining <= 0 {
		return 0, errProtocolPacketTooLarge
	}
	if int64(len(p)) > r.remaining {
		p = p[:int(r.remaining)]
	}
	n, err := r.reader.Read(p)
	r.remaining -= int64(n)
	r.canUnread = false
	return n, err
}

func (r *protocolLimitReader) ReadByte() (byte, error) {
	if r.unreadByte {
		if r.remaining <= 0 {
			return 0, errProtocolPacketTooLarge
		}
		r.unreadByte = false
		r.remaining--
		r.canUnread = true
		return r.lastByte, nil
	}
	if r.remaining <= 0 {
		return 0, errProtocolPacketTooLarge
	}

	var one [1]byte
	if _, err := io.ReadFull(r.reader, one[:]); err != nil {
		return 0, err
	}
	r.remaining--
	r.lastByte = one[0]
	r.canUnread = true
	return one[0], nil
}

func (r *protocolLimitReader) UnreadByte() error {
	if !r.canUnread || r.unreadByte {
		return errors.New("protocol reader: previous operation was not ReadByte")
	}
	r.unreadByte = true
	r.canUnread = false
	r.remaining++
	return nil
}

// LigoloDecoder is the struct containing the decoded Envelope and the reader
type LigoloDecoder struct {
	reader      io.Reader
	limitReader *protocolLimitReader
	decoder     *msgpack.Decoder
	Payload     interface{}
}

// NewDecoder decode Ligolo-ng Relay packets
func NewDecoder(reader io.Reader) LigoloDecoder {
	limitReader := newProtocolLimitReader(reader)
	return LigoloDecoder{
		reader:      reader,
		limitReader: limitReader,
		decoder:     msgpack.NewDecoder(limitReader),
	}
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
	case MessageRelayRequest:
		return &RelayRequestPacket{}, nil
	case MessageRelayResponse:
		return &RelayResponsePacket{}, nil
	case MessageRelayNewConnection:
		return &RelayNewConnectionPacket{}, nil
	case MessageRelayBridgeRequest:
		return &RelayBridgeRequestPacket{}, nil
	case MessageRelayEvent:
		return &RelayEventPacket{}, nil
	case MessageAgentReconnectRequest:
		return &AgentReconnectRequestPacket{}, nil
	case MessageAgentReconnectResponse:
		return &AgentReconnectResponsePacket{}, nil
	default:
		return nil, fmt.Errorf("decode called for unknown payload type: %d", payloadType)
	}
}

// Decode read content from the reader and fill the Envelope
func (d *LigoloDecoder) Decode() error {
	if d.limitReader == nil || d.decoder == nil {
		d.limitReader = newProtocolLimitReader(d.reader)
		d.decoder = msgpack.NewDecoder(d.limitReader)
	}
	d.limitReader.Reset()

	var payloadType uint8
	err := d.decoder.Decode(&payloadType)
	if err != nil {
		return fmt.Errorf("decoder: unable to decode payload type: %v", err)
	}
	p, err := interfaceFromPayloadType(payloadType)
	if err != nil {
		return fmt.Errorf("decoder: unable to get interface from payload: %v", err)
	}

	if err := d.decoder.Decode(p); err != nil {
		return fmt.Errorf("decoder: unable to decode payload: %v", err)
	}
	d.Payload = p

	return nil
}
