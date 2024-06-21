package protocol

import (
	"encoding/gob"
	"io"
)

// LigoloDecoder is the struct containing the decoded Envelope and the reader
type LigoloDecoder struct {
	reader   io.Reader
	Envelope Envelope
}

// NewDecoder decode Ligolo-ng packets
func NewDecoder(reader io.Reader) LigoloDecoder {
	return LigoloDecoder{reader: reader}
}

// Decode read content from the reader and fill the Envelope
func (d *LigoloDecoder) Decode() error {
	gobdecoder := gob.NewDecoder(d.reader)

	if err := gobdecoder.Decode(&d.Envelope); err != nil {
		return err
	}

	return nil
}
