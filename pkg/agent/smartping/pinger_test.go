package smartping

import (
	"fmt"
	"testing"
)

func TestRawPinger(t *testing.T) {
	r, err := RawPinger("127.0.0.1")
	if err != nil {
		t.Error(err)
	}
	fmt.Print(r)
}

func TestCommandPinger(t *testing.T) {
	r, err := CommandPinger("127.0.0.1")
	if err != nil {
		t.Error(err)
	}
	fmt.Print(r)
}
