// Ligolo-ng Relay
// Copyright (C) 2025 Nicolas Chatelain (nicocha30)

package agent

import (
	"net"
	"testing"
	"time"
)

func TestRelayAuthHandshakeAcceptsMatchingToken(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	token := "relay-secret"
	errCh := make(chan error, 1)
	go func() {
		errCh <- verifyRelayAuth(server, RelayAuthTokenHash(token), time.Now().Add(time.Minute).Unix())
	}()

	if err := WriteRelayAuth(client, token); err != nil {
		t.Fatalf("write relay auth: %v", err)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("verify relay auth: %v", err)
	}
}

func TestRelayAuthHandshakeRejectsWrongToken(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	errCh := make(chan error, 1)
	go func() {
		errCh <- verifyRelayAuth(server, RelayAuthTokenHash("expected"), time.Now().Add(time.Minute).Unix())
	}()

	if err := WriteRelayAuth(client, "wrong"); err != nil {
		t.Fatalf("write relay auth: %v", err)
	}
	if err := <-errCh; err == nil {
		t.Fatal("verify relay auth succeeded with wrong token")
	}
}

func TestRelayAuthHandshakeAllowsEmptyHash(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	if err := verifyRelayAuth(server, "", 0); err != nil {
		t.Fatalf("verify relay auth with empty hash: %v", err)
	}
}

func TestRelayAuthHandshakeRejectsExpiredToken(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	token := "relay-secret"
	errCh := make(chan error, 1)
	go func() {
		errCh <- verifyRelayAuth(server, RelayAuthTokenHash(token), time.Now().Add(-time.Minute).Unix())
	}()

	if err := WriteRelayAuth(client, token); err != nil {
		t.Fatalf("write relay auth: %v", err)
	}
	if err := <-errCh; err == nil {
		t.Fatal("verify relay auth succeeded with expired token")
	}
}

func TestRelayAuthSlotsRejectWhenFull(t *testing.T) {
	acquired := 0
	defer func() {
		for ; acquired > 0; acquired-- {
			releaseRelayAuthSlot()
		}
	}()

	for i := 0; i < relayAuthMaxInFlight; i++ {
		if !acquireRelayAuthSlot() {
			t.Fatalf("acquire relay auth slot %d failed before cap", i)
		}
		acquired++
	}

	if acquireRelayAuthSlot() {
		releaseRelayAuthSlot()
		t.Fatal("acquired relay auth slot after cap")
	}
}

func TestRelayPendingSlotsRejectWhenFull(t *testing.T) {
	acquired := 0
	defer func() {
		for ; acquired > 0; acquired-- {
			releaseRelayPendingSlot()
		}
	}()

	for i := 0; i < relayPendingMax; i++ {
		if !acquireRelayPendingSlot() {
			t.Fatalf("acquire relay pending slot %d failed before cap", i)
		}
		acquired++
	}

	if acquireRelayPendingSlot() {
		releaseRelayPendingSlot()
		t.Fatal("acquired relay pending slot after cap")
	}
}

func TestRemoveRelayPendingConnReleasesSlot(t *testing.T) {
	acquired := 0
	defer func() {
		for ; acquired > 0; acquired-- {
			releaseRelayPendingSlot()
		}
	}()

	if !acquireRelayPendingSlot() {
		t.Fatal("acquire relay pending slot failed")
	}
	acquired++

	client, server := net.Pipe()
	defer client.Close()
	relayPendingConns.Store(int32(-1), server)

	for i := acquired; i < relayPendingMax; i++ {
		if !acquireRelayPendingSlot() {
			t.Fatalf("acquire relay pending slot %d failed before cap", i)
		}
		acquired++
	}

	if acquireRelayPendingSlot() {
		releaseRelayPendingSlot()
		t.Fatal("acquired relay pending slot after cap")
	}

	conn, ok := removeRelayPendingConn(int32(-1))
	if !ok {
		t.Fatal("remove relay pending conn failed")
	}
	acquired--
	conn.Close()

	if !acquireRelayPendingSlot() {
		t.Fatal("relay pending slot was not released")
	}
	acquired++
}
