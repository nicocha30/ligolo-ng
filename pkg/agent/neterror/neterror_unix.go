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

//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris
// +build aix darwin dragonfly freebsd linux netbsd openbsd solaris

package neterror

import (
	"errors"
	"syscall"
)

func HostResponded(err error) bool {
	var se syscall.Errno
	if errors.As(err, &se) {
		return errors.Is(se, syscall.ECONNRESET) || errors.Is(se, syscall.ECONNABORTED) || errors.Is(se, syscall.ECONNREFUSED) // added ECONNREFUSED for handling "connection refused"
	}
	return false
}
