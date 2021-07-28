package smartping

import (
	"github.com/go-ping/ping"
	"os/exec"
	"runtime"
	"time"
)

// TryResolve tries to discover if the remote host is up using ICMP
func TryResolve(address string) bool {
	methods := []func(string) (bool, error){
		RawPinger,
		CommandPinger,
	}
	for _, method := range methods {
		if result, err := method(address); err == nil {
			return result
		}
	}
	// Everything failed...
	return false
}

// RawPinger use ICMP sockets to discover if a host is up. This could require administrative permissions on some hosts
func RawPinger(target string) (bool, error) {
	pinger, err := ping.NewPinger(target)
	if err != nil {
		return false, err
	}
	pinger.Count = 1
	pinger.Timeout = 4 * time.Second // NMAP default timeout ?
	if runtime.GOOS == "windows" {
		pinger.SetPrivileged(true)
	}
	err = pinger.Run()
	if err != nil {
		return false, err
	}

	return pinger.PacketsRecv != 0, nil
}

// CommandPinger uses the internal ping command (dirty), but should not require privileges
func CommandPinger(target string) (bool, error) {
	countArg := "-c"
	waitArg := "-W"
	waitTime := "3"
	if runtime.GOOS == "windows" {
		countArg = "/n"
		waitArg = "/w"
		waitTime = "3000"
	}

	cmd := exec.Command("ping", countArg, "1", waitArg, waitTime, target)
	if err := cmd.Run(); err != nil {
		return false, err
	}
	return true, nil
}
