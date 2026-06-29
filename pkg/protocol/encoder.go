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
	"fmt"
	"io"

	"github.com/vmihailenco/msgpack/v5"
)

// LigoloEncoder is the structure containing the writer used when encoding Envelopes
type LigoloEncoder struct {
	writer  io.Writer
	encoder *msgpack.Encoder
}

// NewEncoder encode Ligolo-ng Relay packets
func NewEncoder(writer io.Writer) LigoloEncoder {
	return LigoloEncoder{writer: writer, encoder: msgpack.NewEncoder(writer)}
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
	case AgentKillRequestPacket:
		return MessageAgentKillRequest, nil
	case ListenerSocketConnectionReady:
		return MessageListenerSocketConnectionReady, nil
	case RelayRequestPacket:
		return MessageRelayRequest, nil
	case RelayResponsePacket:
		return MessageRelayResponse, nil
	case RelayNewConnectionPacket:
		return MessageRelayNewConnection, nil
	case RelayBridgeRequestPacket:
		return MessageRelayBridgeRequest, nil
	case RelayEventPacket:
		return MessageRelayEvent, nil
	case AgentReconnectRequestPacket:
		return MessageAgentReconnectRequest, nil
	case AgentReconnectResponsePacket:
		return MessageAgentReconnectResponse, nil
	default:
		return 0, fmt.Errorf("payloadTypeFromInterface called for unknown payload type: %v", payload)
	}
}

// Encode an Envelope packet and write the result into the writer
func (e *LigoloEncoder) Encode(payload interface{}) error {
	payloadType, err := payloadTypeFromInterface(payload)
	if err != nil {
		return err
	}

	if e.encoder == nil {
		e.encoder = msgpack.NewEncoder(e.writer)
	}

	if err := e.encoder.Encode(payloadType); err != nil {
		return err
	}

	if err := e.encoder.Encode(payload); err != nil {
		return err
	}

	return nil
}
