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
