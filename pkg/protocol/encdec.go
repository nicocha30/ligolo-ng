package protocol

import "io"

type LigoloEncoderDecoder struct {
	LigoloDecoder
	LigoloEncoder
}

func NewEncoderDecoder(rw io.ReadWriter) LigoloEncoderDecoder {
	return LigoloEncoderDecoder{
		NewDecoder(rw),
		NewEncoder(rw),
	}
}
