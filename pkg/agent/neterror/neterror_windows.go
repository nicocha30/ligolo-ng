package neterror

import (
	"errors"
	"syscall"
)

func HostResponded(err error) bool {
	var se syscall.Errno
	if errors.As(err, &se) {
		return errors.Is(se, syscall.WSAECONNRESET) || errors.Is(se, syscall.WSAECONNABORTED)
	}
	return false
}
