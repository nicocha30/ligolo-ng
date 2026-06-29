// Ligolo-ng Relay
// Copyright (C) 2025 Nicolas Chatelain (nicocha30)

package relayapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestDoAuthenticatesWhenNoToken(t *testing.T) {
	var authCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/auth":
			authCalls.Add(1)
			_, _ = w.Write([]byte(`{"token":"jwt1"}`))
		case "/api/v1/agents":
			if r.Header.Get("Authorization") != "jwt1" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_, _ = w.Write([]byte(`[]`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	c := New(Config{BaseURL: server.URL, Username: "u", Password: "p", HTTPClient: server.Client()})
	if _, err := c.Do(context.Background(), "GET", "/api/v1/agents", nil); err != nil {
		t.Fatalf("Do: %v", err)
	}
	if authCalls.Load() != 1 {
		t.Fatalf("auth calls = %d, want 1", authCalls.Load())
	}
}

func TestDoRefreshesOnUnauthorized(t *testing.T) {
	var authCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/auth":
			authCalls.Add(1)
			_, _ = w.Write([]byte(`{"token":"fresh"}`))
		case "/api/v1/agents":
			// Only the freshly-minted token is accepted; the stale one 401s.
			if r.Header.Get("Authorization") != "fresh" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_, _ = w.Write([]byte(`[]`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	c := New(Config{BaseURL: server.URL, Username: "u", Password: "p", Token: "stale", HTTPClient: server.Client()})
	if _, err := c.Do(context.Background(), "GET", "/api/v1/agents", nil); err != nil {
		t.Fatalf("Do: %v", err)
	}
	if authCalls.Load() != 1 {
		t.Fatalf("auth calls = %d, want 1 (refresh after 401)", authCalls.Load())
	}
}

func TestDoCannotRefreshWithoutCredentials(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	c := New(Config{BaseURL: server.URL, Token: "stale", HTTPClient: server.Client()})
	_, err := c.Do(context.Background(), "GET", "/api/v1/agents", nil)
	if err == nil {
		t.Fatal("Do succeeded, want unauthorized error")
	}
	if !strings.Contains(err.Error(), "HTTP 401") {
		t.Fatalf("error = %v, want HTTP 401", err)
	}
}

func TestDoWithoutTokenOrCredentials(t *testing.T) {
	c := New(Config{BaseURL: "http://127.0.0.1:0"})
	_, err := c.Do(context.Background(), "GET", "/api/v1/agents", nil)
	if err == nil || !strings.Contains(err.Error(), "not authenticated") {
		t.Fatalf("error = %v, want not authenticated", err)
	}
}

func TestDoPropagatesServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"boom"}`))
	}))
	defer server.Close()

	c := New(Config{BaseURL: server.URL, Token: "t", HTTPClient: server.Client()})
	_, err := c.Do(context.Background(), "GET", "/api/v1/ping", nil)
	if err == nil {
		t.Fatal("Do succeeded, want server error")
	}
	if !strings.Contains(err.Error(), "HTTP 500") || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("error = %v, want HTTP 500 + body", err)
	}
}

func TestAuthFailureSurfaced(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/auth" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"invalid credentials"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	c := New(Config{BaseURL: server.URL, Username: "u", Password: "bad", HTTPClient: server.Client()})
	_, err := c.Do(context.Background(), "GET", "/api/v1/ping", nil)
	if err == nil || !strings.Contains(err.Error(), "auth failed") {
		t.Fatalf("error = %v, want auth failed", err)
	}
}
