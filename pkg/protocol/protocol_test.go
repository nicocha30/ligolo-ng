package protocol

import (
	"bytes"
	"io"
	"testing"
)

func TestEncodeDecode(t *testing.T) {
	var buffer bytes.Buffer

	baseEnveloppe := Envelope{
		Type:    MessageInfoReply,
		Payload: InfoReplyPacket{Name: "hello"},
	}
	enc := NewEncoder(&buffer)
	if err := enc.Encode(baseEnveloppe); err != nil {
		t.Fatal(err)
	}

	dec := NewDecoder(&buffer)
	if err := dec.Decode(); err != nil {
		if err != io.EOF {
			t.Fatal(err)
		}
	}

	if dec.Envelope.Payload.(InfoReplyPacket).Name != "hello" {
		t.Fatal("invalid packet decoded")
	}

}
