package relay

import (
	"io"
	"net"
)

func relay(src net.Conn, dst net.Conn, stop chan bool) {
	io.Copy(dst, src)
	dst.Close()
	src.Close()
	stop <- true
	return
}

func StartRelay(src net.Conn, dst net.Conn) {
	stop := make(chan bool, 2)

	go relay(src, dst, stop)
	go relay(dst, src, stop)

	select {
	case <-stop:
		return
	}
}
