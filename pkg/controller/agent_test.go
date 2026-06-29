// Ligolo-ng Relay
// Copyright (C) 2025 Nicolas Chatelain (nicocha30)

package controller

import (
	"strings"
	"testing"
	"time"
)

func TestRelayStatusSnapshotTracksTokenAndRecentEvents(t *testing.T) {
	agent := &LigoloAgent{
		RelayTokenExpiresAt: time.Now().Add(-time.Minute),
		RelayOneTimeToken:   true,
	}

	for i := 0; i < maxRelayEvents+3; i++ {
		agent.RecordRelayEvent("relay_event", "", strings.Repeat("x", i+1))
	}
	agent.RecordRelayEvent("downstream_authenticated", "10.0.0.5:4444", "downstream relay auth accepted")
	agent.RecordRelayEvent("auth_rejected", "10.0.0.6:4444", "relay auth token rejected")

	status := agent.RelayStatusSnapshot()
	if !status.TokenExpired {
		t.Fatal("expected expired token status")
	}
	if !status.OneTimeToken || !status.OneTimeTokenUsed {
		t.Fatalf("one-time token status not tracked: %+v", status)
	}
	if status.LastError != "relay auth token rejected" {
		t.Fatalf("last error = %q, want relay auth token rejected", status.LastError)
	}
	if len(status.RecentEvents) != maxRelayEvents {
		t.Fatalf("recent event count = %d, want %d", len(status.RecentEvents), maxRelayEvents)
	}
	if status.RecentEvents[len(status.RecentEvents)-1].Kind != "auth_rejected" {
		t.Fatalf("latest event = %+v, want auth_rejected", status.RecentEvents[len(status.RecentEvents)-1])
	}
}

func TestStartRelayWithOptionsRejectsExpiredTokenBeforeOpeningSession(t *testing.T) {
	agent := &LigoloAgent{
		Name:         "root@agent-a",
		RelayCapable: true,
	}

	_, err := agent.StartRelayWithOptions(RelayStartOptions{
		ListenAddr:     "127.0.0.1:11602",
		AuthToken:      "relay-secret",
		TokenExpiresAt: time.Now().Add(-time.Minute),
	})
	if err == nil {
		t.Fatal("expected expired token error")
	}
	if !strings.Contains(err.Error(), "expiry") {
		t.Fatalf("unexpected error: %v", err)
	}
}
