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

import (
	"fmt"
	"net/url"
	"strings"
)

type LigoloURL struct {
	*url.URL
}

func (l *LigoloURL) IsSecure() bool {
	if l.Scheme == "https" || l.Scheme == "wss" {
		return true
	}
	return false
}

func (l *LigoloURL) IsWebsocket() bool {
	if l.Scheme == "http" || l.Scheme == "ws" || l.Scheme == "https" || l.Scheme == "wss" {
		return true
	}
	return false
}

func (l *LigoloURL) IsValid() bool {
	return l.IsWebsocket() || l.Scheme == ""
}

func ParseLigoloURL(rawURL string) (*LigoloURL, error) {
	u, err := url.Parse(rawURL)

	if err != nil {
		if urlErr, ok := err.(*url.Error); ok && strings.Contains(urlErr.Err.Error(), "first path segment") {
			u, err := url.Parse("//" + rawURL)
			if err != nil {
				return nil, err
			}
			return &LigoloURL{u}, nil
		}
		return nil, err
	}

	return &LigoloURL{u}, nil
}

func printURL(title string, u *url.URL) {
	fmt.Printf("--- %s ---\n", title)
	if u == nil {
		fmt.Println("  URL is nil")
		fmt.Println()
		return
	}
	fmt.Printf("  String() : %s\n", u.String())
	fmt.Printf("  Scheme   : %q\n", u.Scheme)
	fmt.Printf("  Host     : %q\n", u.Host)
	fmt.Printf("  Path     : %q\n", u.Path)
	fmt.Printf("  Opaque   : %q\n", u.Opaque)
	fmt.Println()
}

func main() {
	urlsToTest := []string{
		"wss://foo.bar:8080/path/to",
		"https://foo.bar",
		"ws://127.0.0.1:11601",
		"127.0.0.1:11601",
	}

	for _, raw := range urlsToTest {
		fmt.Printf("Processing: %q\n", raw)
		u, err := ParseLigoloURL(raw)
		if err != nil {
			fmt.Printf("Error: %v\n\n", err)
			continue
		}
		printURL(raw, u.URL)
	}
}
