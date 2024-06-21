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
