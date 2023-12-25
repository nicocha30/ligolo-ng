package relay

import (
	"io"
	"net"
)

func relay(src net.Conn, dst net.Conn, stop chan error, closeOnError bool) {
	_, err := io.Copy(dst, src)
	if closeOnError {
		dst.Close()
		src.Close()
	}

	stop <- err
	return
}

func StartRelay(src net.Conn, dst net.Conn) error {
	stop := make(chan error, 2)

	go relay(src, dst, stop, true)
	go relay(dst, src, stop, true)

	select {
	case err := <-stop:
		return err
	}
}

func StartPacketRelay(src net.Conn, dst net.Conn) error {
	stop := make(chan error, 2)

	go relay(src, dst, stop, false)
	go relay(dst, src, stop, false)

	select {
	case err := <-stop:
		return err
	}
}
