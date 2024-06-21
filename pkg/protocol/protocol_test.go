package protocol

import (
	"bytes"
	"fmt"
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

	fmt.Printf("Envelope created: %+v\n", buffer)

	dec := NewDecoder(&buffer)
	if err := dec.Decode(); err != nil {
		if err != io.EOF {
			t.Fatal(err)
		}
	}

	fmt.Printf("Envelope: %+v\n", dec.Envelope)

	if dec.Envelope.Payload.(InfoReplyPacket).Name != "hello" {
		t.Fatal("invalid packet decoded")
	}

}
