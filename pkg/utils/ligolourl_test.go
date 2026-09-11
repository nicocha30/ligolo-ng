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

package utils

import "testing"

func TestParseLigoloURL(t *testing.T) {
	tests := []struct {
		name        string
		rawURL      string
		wantHost    string
		wantScheme  string
		wantWebsock bool
	}{
		{
			// Regression: a "host:port" string with a letter-only host is
			// parsed by url.Parse as scheme:opaque, leaving Host empty.
			// The agent then sets an empty TLS ServerName (no SNI sent).
			name:       "hostname with port (TCP)",
			rawURL:     "tunnel.example.com:443",
			wantHost:   "tunnel.example.com:443",
			wantScheme: "",
		},
		{
			name:       "hostname without port (TCP)",
			rawURL:     "tunnel.example.com",
			wantHost:   "tunnel.example.com",
			wantScheme: "",
		},
		{
			name:       "IPv4 with port (TCP)",
			rawURL:     "127.0.0.1:11601",
			wantHost:   "127.0.0.1:11601",
			wantScheme: "",
		},
		{
			name:        "wss websocket",
			rawURL:      "wss://foo.bar:8080/path/to",
			wantHost:    "foo.bar:8080",
			wantScheme:  "wss",
			wantWebsock: true,
		},
		{
			name:        "https websocket",
			rawURL:      "https://foo.bar",
			wantHost:    "foo.bar",
			wantScheme:  "https",
			wantWebsock: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := ParseLigoloURL(tt.rawURL)
			if err != nil {
				t.Fatalf("ParseLigoloURL(%q) returned error: %v", tt.rawURL, err)
			}
			if u.Host != tt.wantHost {
				t.Errorf("ParseLigoloURL(%q).Host = %q, want %q", tt.rawURL, u.Host, tt.wantHost)
			}
			if u.Scheme != tt.wantScheme {
				t.Errorf("ParseLigoloURL(%q).Scheme = %q, want %q", tt.rawURL, u.Scheme, tt.wantScheme)
			}
			if u.IsWebsocket() != tt.wantWebsock {
				t.Errorf("ParseLigoloURL(%q).IsWebsocket() = %v, want %v", tt.rawURL, u.IsWebsocket(), tt.wantWebsock)
			}
			if !u.IsValid() {
				t.Errorf("ParseLigoloURL(%q).IsValid() = false, want true", tt.rawURL)
			}
		})
	}
}
