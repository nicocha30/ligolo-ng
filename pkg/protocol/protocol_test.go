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
	"bytes"
	"fmt"
	"io"
	"testing"
)

func TestEncodeDecode(t *testing.T) {
	var buffer bytes.Buffer

	baseEnvelope := InfoReplyPacket{Name: "hello"}
	enc := NewEncoder(&buffer)
	if err := enc.Encode(baseEnvelope); err != nil {
		t.Fatal(err)
	}

	fmt.Printf("Envelope created: %+v\n", buffer)

	dec := NewDecoder(&buffer)
	if err := dec.Decode(); err != nil {
		if err != io.EOF {
			t.Fatal(err)
		}
	}

	fmt.Printf("Envelope: %+v\n", dec.Payload)

	if dec.Payload.(*InfoReplyPacket).Name != "hello" {
		t.Fatal("invalid packet decoded")
	}

}

func TestRelayPackets(t *testing.T) {
	tests := []struct {
		name    string
		packet  interface{}
		checker func(interface{}) bool
	}{
		{
			name:   "RelayRequest",
			packet: RelayRequestPacket{ListenAddr: "0.0.0.0:11602"},
			checker: func(p interface{}) bool {
				pkt := p.(*RelayRequestPacket)
				return pkt.ListenAddr == "0.0.0.0:11602"
			},
		},
		{
			name:   "RelayResponse",
			packet: RelayResponsePacket{Err: false, CertFingerprint: "AABBCCDD"},
			checker: func(p interface{}) bool {
				pkt := p.(*RelayResponsePacket)
				return !pkt.Err && pkt.CertFingerprint == "AABBCCDD"
			},
		},
		{
			name:   "RelayResponseError",
			packet: RelayResponsePacket{Err: true, ErrString: "bind failed"},
			checker: func(p interface{}) bool {
				pkt := p.(*RelayResponsePacket)
				return pkt.Err && pkt.ErrString == "bind failed"
			},
		},
		{
			name:   "RelayNewConnection",
			packet: RelayNewConnectionPacket{ConnectionID: 42, RemoteAddr: "10.0.0.5:54321"},
			checker: func(p interface{}) bool {
				pkt := p.(*RelayNewConnectionPacket)
				return pkt.ConnectionID == 42 && pkt.RemoteAddr == "10.0.0.5:54321"
			},
		},
		{
			name:   "RelayBridgeRequest",
			packet: RelayBridgeRequestPacket{ConnectionID: 42},
			checker: func(p interface{}) bool {
				pkt := p.(*RelayBridgeRequestPacket)
				return pkt.ConnectionID == 42
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buffer bytes.Buffer

			enc := NewEncoder(&buffer)
			if err := enc.Encode(tt.packet); err != nil {
				t.Fatalf("encode error: %v", err)
			}

			dec := NewDecoder(&buffer)
			if err := dec.Decode(); err != nil {
				t.Fatalf("decode error: %v", err)
			}

			if !tt.checker(dec.Payload) {
				t.Fatalf("decoded packet does not match: %+v", dec.Payload)
			}
		})
	}
}

func TestInfoReplyRelayCapable(t *testing.T) {
	var buffer bytes.Buffer

	packet := InfoReplyPacket{Name: "test@host", SessionID: "abc123", RelayCapable: true}
	enc := NewEncoder(&buffer)
	if err := enc.Encode(packet); err != nil {
		t.Fatal(err)
	}

	dec := NewDecoder(&buffer)
	if err := dec.Decode(); err != nil {
		t.Fatal(err)
	}

	reply := dec.Payload.(*InfoReplyPacket)
	if reply.Name != "test@host" || !reply.RelayCapable || reply.SessionID != "abc123" {
		t.Fatalf("unexpected packet: %+v", reply)
	}
}

func BenchmarkEncodeDecode(b *testing.B) {
	for i := 0; i < b.N; i++ {
		var buffer bytes.Buffer
		baseEnvelope := InfoReplyPacket{Name: "hello"}
		enc := NewEncoder(&buffer)
		if err := enc.Encode(baseEnvelope); err != nil {
			b.Fatal(err)
		}

		dec := NewDecoder(&buffer)
		if err := dec.Decode(); err != nil {
			if err != io.EOF {
				b.Fatal(err)
			}
		}

		if dec.Payload.(*InfoReplyPacket).Name != "hello" {
			b.Fatal("invalid packet decoded")
		}
	}
}
