package tun

const offset = 4

// Can we use tun.New on an already existent interface?
func AllowExisting() bool {
	return false
}
