// Ligolo-ng Relay
// Copyright (C) 2025 Nicolas Chatelain (nicocha30)

// Package relaymcp exposes the Ligolo-ng Relay control plane as a set of MCP
// tools. The tool layer talks to a RelayBackend rather than to a concrete
// transport, so the same tools can be served by the standalone relaymcp binary
// (REST backend, talking to the proxy API) or, later, hosted in-process by the
// proxy itself (a backend calling its state directly).
package relaymcp

import (
	"context"
	"encoding/json"
)

// RelayBackend is the operation surface the MCP tools call. Every method
// returns the raw JSON the proxy would return, so tools can pass it straight
// through to the model. Methods are named per operation (not a generic
// Do(method, path)) so an in-process implementation has a clean, typed seam.
type RelayBackend interface {
	// Read-only / diagnostics.
	Ping(ctx context.Context) (json.RawMessage, error)
	ListAgents(ctx context.Context) (json.RawMessage, error)
	GetChains(ctx context.Context) (json.RawMessage, error)
	RelayDoctor(ctx context.Context, opts DiagOptions) (json.RawMessage, error)
	RelayOps(ctx context.Context, opts DiagOptions) (json.RawMessage, error)
	AutohealStatus(ctx context.Context) (json.RawMessage, error)
	ListChainRoutes(ctx context.Context, opts DiagOptions) (json.RawMessage, error)
	ChainRoutePlan(ctx context.Context, opts PlanOptions) (json.RawMessage, error)
	ChainRepairPlan(ctx context.Context, opts RepairOptions) (json.RawMessage, error)
	ChainFailoverPlan(ctx context.Context, includeCommands bool) (json.RawMessage, error)
	ListListeners(ctx context.Context) (json.RawMessage, error)
	ListInterfaces(ctx context.Context) (json.RawMessage, error)

	// Mutating.
	AutohealRun(ctx context.Context, opts AutohealRunOptions) (json.RawMessage, error)
	ChainAutoroute(ctx context.Context, opts AutorouteOptions) (json.RawMessage, error)
	ChainRepairApply(ctx context.Context, opts RepairOptions) (json.RawMessage, error)
	ChainFailoverApply(ctx context.Context, opts FailoverApplyOptions) (json.RawMessage, error)
	RelayStart(ctx context.Context, agentID int, opts RelayStartOptions) (json.RawMessage, error)
	RelayStop(ctx context.Context, agentID int) (json.RawMessage, error)
	RelayTokenRotate(ctx context.Context, agentID int, opts RelayTokenOptions) (json.RawMessage, error)
	RelayTokenRevoke(ctx context.Context, agentID int) (json.RawMessage, error)
	TunnelStart(ctx context.Context, agentID int, iface string) (json.RawMessage, error)
	TunnelStop(ctx context.Context, agentID int) (json.RawMessage, error)
	CreateListener(ctx context.Context, opts ListenerOptions) (json.RawMessage, error)
	DeleteListener(ctx context.Context, agentID, listenerID int) (json.RawMessage, error)
	CreateInterface(ctx context.Context, name string) (json.RawMessage, error)
	DeleteInterface(ctx context.Context, name string) (json.RawMessage, error)
	AddRoute(ctx context.Context, iface string, routes []string) (json.RawMessage, error)
	DeleteRoute(ctx context.Context, iface, route string) (json.RawMessage, error)
}

// DiagOptions are the shared query parameters for diagnostic/route endpoints.
type DiagOptions struct {
	WithIPv6        bool
	InterfacePrefix string
}

// PlanOptions parameterize the dry-run route plan.
type PlanOptions struct {
	WithIPv6        bool
	InterfacePrefix string
	Start           bool
}

// RepairOptions parameterize both the repair dry-run and apply.
type RepairOptions struct {
	WithIPv6        bool
	InterfacePrefix string
	Start           bool
	PruneConflicts  bool
}

// AutorouteOptions parameterize chain autoroute application.
type AutorouteOptions struct {
	WithIPv6        bool
	InterfacePrefix string
	Start           bool
}

// FailoverApplyOptions parameterize failover application. Apply requires All,
// or at least one of SessionIDs / AgentIDs.
type FailoverApplyOptions struct {
	IncludeCommands bool
	All             bool
	SessionIDs      []string
	AgentIDs        []int
}

// AutohealRunOptions parameterize a one-shot auto-heal run. Fields are pointers
// because the proxy only overrides policy when a value is supplied; nil
// preserves the server-side configured default.
type AutohealRunOptions struct {
	Apply            *bool
	WithIPv6         *bool
	InterfacePrefix  *string
	StartTunnels     *bool
	Repair           *bool
	PruneConflicts   *bool
	Failover         *bool
	MaxRepairActions *int
	MaxFailovers     *int
}

// RelayStartOptions parameterize starting relay mode on an agent.
type RelayStartOptions struct {
	ListenAddr      string
	AuthToken       string
	TokenTTLSeconds int64
	OneTimeToken    bool
}

// RelayTokenOptions parameterize relay token rotation.
type RelayTokenOptions struct {
	AuthToken       string
	TokenTTLSeconds int64
	OneTimeToken    bool
}

// ListenerOptions parameterize creating a listener/redirector on an agent.
type ListenerOptions struct {
	AgentID      int
	ListenerAddr string
	RedirectAddr string
	Network      string
}
