// Ligolo-ng Relay
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

package smartping

import (
	"errors"
	"os"
	"strings"
	"testing"
)

func TestRawPinger(t *testing.T) {
	r, err := RawPinger("127.0.0.1")
	if err != nil {
		if isPermissionError(err) {
			t.Skipf("raw ICMP socket requires elevated permissions: %v", err)
		}
		t.Fatal(err)
	}
	if !r {
		t.Fatal("expected localhost to respond to raw ping")
	}
}

func isPermissionError(err error) bool {
	return errors.Is(err, os.ErrPermission) || strings.Contains(strings.ToLower(err.Error()), "permission denied")
}

func TestCommandPinger(t *testing.T) {
	r, err := CommandPinger("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if !r {
		t.Fatal("expected localhost to respond to command ping")
	}
}
