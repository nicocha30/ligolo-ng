//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris
// +build aix darwin dragonfly freebsd linux netbsd openbsd solaris

package neterror

import (
	"syscall"
)

func HostResponded(err error) bool {
	if se, ok := err.(syscall.Errno); ok {
		return se == syscall.ECONNRESET || se == syscall.ECONNABORTED || se == syscall.ECONNREFUSED // added ECONNREFUSED for handling "connection refused"
	}
	return false
}
