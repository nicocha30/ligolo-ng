package neterror

import "syscall"

func HostResponded(err error) bool {
	if se, ok := err.(syscall.Errno); ok {
		return se == syscall.WSAECONNRESET || se == syscall.WSAECONNABORTED
	}
	return false
}
