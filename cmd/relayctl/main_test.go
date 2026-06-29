// Ligolo-ng Relay
// Copyright (C) 2025 Nicolas Chatelain (nicocha30)

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/allsmog/ligolo-ng-relay/pkg/relayapi"
)

func TestParseTokenTTLSeconds(t *testing.T) {
	seconds, err := parseTokenTTLSeconds("30m")
	if err != nil {
		t.Fatalf("parse token TTL: %v", err)
	}
	if seconds != 1800 {
		t.Fatalf("seconds = %d, want 1800", seconds)
	}
}

func TestParseTokenTTLSecondsRejectsInvalidValues(t *testing.T) {
	for _, value := range []string{"", "0s", "-1m", "forever"} {
		if _, err := parseTokenTTLSeconds(value); err == nil {
			t.Fatalf("parse token TTL %q succeeded, want error", value)
		}
	}
}

func TestRunOpsFailsOnWarning(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/relay/ops" {
			t.Fatalf("path = %q, want /api/v1/relay/ops", r.URL.Path)
		}
		if got := r.URL.Query().Get("with_ipv6"); got != "true" {
			t.Fatalf("with_ipv6 = %q, want true", got)
		}
		if got := r.URL.Query().Get("interface_prefix"); got != "relaytest" {
			t.Fatalf("interface_prefix = %q, want relaytest", got)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"warning","summary":{"warnings":1}}`))
	}))
	defer server.Close()

	c := relayapi.New(relayapi.Config{
		BaseURL:    server.URL,
		Token:      "test-token",
		HTTPClient: server.Client(),
	})
	err := runOps(c, []string{"--with-ipv6", "--interface-prefix", "relaytest", "--fail-on-warning"})
	if err == nil {
		t.Fatal("runOps succeeded, want warning error")
	}
	if !strings.Contains(err.Error(), `relay ops status is "warning"`) {
		t.Fatalf("runOps error = %v", err)
	}
}

func TestRunChainPlanQueriesPlanEndpoint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/chain_route_plan" {
			t.Fatalf("path = %q, want /api/v1/chain_route_plan", r.URL.Path)
		}
		if got := r.URL.Query().Get("with_ipv6"); got != "true" {
			t.Fatalf("with_ipv6 = %q, want true", got)
		}
		if got := r.URL.Query().Get("interface_prefix"); got != "relaytest" {
			t.Fatalf("interface_prefix = %q, want relaytest", got)
		}
		if got := r.URL.Query().Get("start"); got != "true" {
			t.Fatalf("start = %q, want true", got)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok","summary":{"apply":1},"decisions":[]}`))
	}))
	defer server.Close()

	c := relayapi.New(relayapi.Config{
		BaseURL:    server.URL,
		Token:      "test-token",
		HTTPClient: server.Client(),
	})
	if err := runChainPlan(c, []string{"--with-ipv6", "--interface-prefix", "relaytest", "--start"}); err != nil {
		t.Fatalf("runChainPlan: %v", err)
	}
}

func TestRunChainRepairQueriesPlanEndpoint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/chain_repair_plan" {
			t.Fatalf("path = %q, want /api/v1/chain_repair_plan", r.URL.Path)
		}
		if got := r.URL.Query().Get("with_ipv6"); got != "true" {
			t.Fatalf("with_ipv6 = %q, want true", got)
		}
		if got := r.URL.Query().Get("interface_prefix"); got != "relaytest" {
			t.Fatalf("interface_prefix = %q, want relaytest", got)
		}
		if got := r.URL.Query().Get("start"); got != "true" {
			t.Fatalf("start = %q, want true", got)
		}
		if got := r.URL.Query().Get("prune_conflicts"); got != "true" {
			t.Fatalf("prune_conflicts = %q, want true", got)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"warning","summary":{"actions":1},"actions":[]}`))
	}))
	defer server.Close()

	c := relayapi.New(relayapi.Config{
		BaseURL:    server.URL,
		Token:      "test-token",
		HTTPClient: server.Client(),
	})
	if err := runChainRepair(c, []string{"--with-ipv6", "--interface-prefix", "relaytest", "--start", "--prune-conflicts"}); err != nil {
		t.Fatalf("runChainRepair: %v", err)
	}
}

func TestRunChainRepairApplyPostsRepairRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/chain_repair" {
			t.Fatalf("path = %q, want /api/v1/chain_repair", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Fatalf("method = %q, want POST", r.Method)
		}
		var req struct {
			WithIPv6        bool
			InterfacePrefix string
			Start           bool
			PruneConflicts  bool
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if !req.WithIPv6 || req.InterfacePrefix != "relaytest" || !req.Start || !req.PruneConflicts {
			t.Fatalf("request = %+v, want all chain repair flags set", req)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"warning","summary":{"applied":1},"actions":[]}`))
	}))
	defer server.Close()

	c := relayapi.New(relayapi.Config{
		BaseURL:    server.URL,
		Token:      "test-token",
		HTTPClient: server.Client(),
	})
	if err := runChainRepair(c, []string{"--with-ipv6", "--interface-prefix", "relaytest", "--start", "--prune-conflicts", "--apply"}); err != nil {
		t.Fatalf("runChainRepair apply: %v", err)
	}
}

func TestRunChainFailoverQueriesPlanEndpoint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/chain_failover_plan" {
			t.Fatalf("path = %q, want /api/v1/chain_failover_plan", r.URL.Path)
		}
		if got := r.URL.Query().Get("include_commands"); got != "true" {
			t.Fatalf("include_commands = %q, want true", got)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"warning","summary":{"recommendations":1},"recommendations":[]}`))
	}))
	defer server.Close()

	c := relayapi.New(relayapi.Config{
		BaseURL:    server.URL,
		Token:      "test-token",
		HTTPClient: server.Client(),
	})
	if err := runChainFailover(c, []string{"--include-commands"}); err != nil {
		t.Fatalf("runChainFailover: %v", err)
	}
}

func TestRunChainFailoverApplyPostsRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/chain_failover" {
			t.Fatalf("path = %q, want /api/v1/chain_failover", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Fatalf("method = %q, want POST", r.Method)
		}
		var req struct {
			IncludeCommands bool
			All             bool
			SessionIDs      []string
			AgentIDs        []int
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if !req.IncludeCommands || req.All {
			t.Fatalf("request include/all = %+v, want include commands only", req)
		}
		if len(req.SessionIDs) != 1 || req.SessionIDs[0] != "agent-c" {
			t.Fatalf("session IDs = %+v, want agent-c", req.SessionIDs)
		}
		if len(req.AgentIDs) != 2 || req.AgentIDs[0] != 2 || req.AgentIDs[1] != 3 {
			t.Fatalf("agent IDs = %+v, want 2,3", req.AgentIDs)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"warning","summary":{"applied":1},"recommendations":[]}`))
	}))
	defer server.Close()

	c := relayapi.New(relayapi.Config{
		BaseURL:    server.URL,
		Token:      "test-token",
		HTTPClient: server.Client(),
	})
	err := runChainFailover(c, []string{"--apply", "--include-commands", "--sessions", "agent-c", "--agents", "2,3"})
	if err != nil {
		t.Fatalf("runChainFailover apply: %v", err)
	}
}

func TestRunChainFailoverApplyRequiresSelector(t *testing.T) {
	c := relayapi.New(relayapi.Config{})
	err := runChainFailover(c, []string{"--apply"})
	if err == nil {
		t.Fatal("runChainFailover apply succeeded, want selector error")
	}
	if !strings.Contains(err.Error(), "requires --all, --sessions, or --agents") {
		t.Fatalf("error = %v", err)
	}
}

func TestRunAutoHealQueriesStatusEndpoint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/relay/autoheal" {
			t.Fatalf("path = %q, want /api/v1/relay/autoheal", r.URL.Path)
		}
		if r.Method != http.MethodGet {
			t.Fatalf("method = %q, want GET", r.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"running":false,"policy":{"enabled":false}}`))
	}))
	defer server.Close()

	c := relayapi.New(relayapi.Config{
		BaseURL:    server.URL,
		Token:      "test-token",
		HTTPClient: server.Client(),
	})
	if err := runAutoHeal(c, nil); err != nil {
		t.Fatalf("runAutoHeal: %v", err)
	}
}

func TestRunAutoHealRunPostsPolicyRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/relay/autoheal/run" {
			t.Fatalf("path = %q, want /api/v1/relay/autoheal/run", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Fatalf("method = %q, want POST", r.Method)
		}
		var req struct {
			Apply            bool
			WithIPv6         bool
			InterfacePrefix  string
			StartTunnels     bool
			Repair           bool
			PruneConflicts   bool
			Failover         bool
			MaxRepairActions int
			MaxFailovers     int
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if !req.Apply || !req.WithIPv6 || req.InterfacePrefix != "relaytest" || !req.StartTunnels || !req.PruneConflicts {
			t.Fatalf("request flags = %+v, want apply, IPv6, relaytest, start, prune", req)
		}
		if req.Repair || !req.Failover {
			t.Fatalf("repair/failover = %+v, want repair disabled and failover enabled", req)
		}
		if req.MaxRepairActions != 3 || req.MaxFailovers != 2 {
			t.Fatalf("limits = %d/%d, want 3/2", req.MaxRepairActions, req.MaxFailovers)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"warning","mode":"apply","applied":1}`))
	}))
	defer server.Close()

	c := relayapi.New(relayapi.Config{
		BaseURL:    server.URL,
		Token:      "test-token",
		HTTPClient: server.Client(),
	})
	err := runAutoHeal(c, []string{
		"--run",
		"--apply",
		"--with-ipv6",
		"--interface-prefix", "relaytest",
		"--start",
		"--prune-conflicts",
		"--repair=false",
		"--max-repair-actions", "3",
		"--max-failovers", "2",
	})
	if err != nil {
		t.Fatalf("runAutoHeal run: %v", err)
	}
}
