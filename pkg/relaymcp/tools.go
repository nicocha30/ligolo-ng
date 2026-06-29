// Ligolo-ng Relay
// Copyright (C) 2025 Nicolas Chatelain (nicocha30)

package relaymcp

import (
	"context"
	"encoding/json"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// --- annotation helpers ---

func ptrBool(b bool) *bool { return &b }

func readOnlyAnnotations() *mcp.ToolAnnotations {
	return &mcp.ToolAnnotations{ReadOnlyHint: true}
}

// additiveAnnotations marks a write tool that only adds/changes state without
// destroying existing resources (DestructiveHint=false).
func additiveAnnotations() *mcp.ToolAnnotations {
	return &mcp.ToolAnnotations{DestructiveHint: ptrBool(false)}
}

// destructiveAnnotations marks a write tool that may tear down or disrupt
// existing resources (stop/delete/revoke/failover/apply-repairs).
func destructiveAnnotations() *mcp.ToolAnnotations {
	return &mcp.ToolAnnotations{DestructiveHint: ptrBool(true)}
}

// destructiveIdempotentAnnotations marks a destructive tool that is safe to
// repeat with the same arguments (e.g. stop/revoke).
func destructiveIdempotentAnnotations() *mcp.ToolAnnotations {
	return &mcp.ToolAnnotations{DestructiveHint: ptrBool(true), IdempotentHint: true}
}

// toolResult wraps a backend call's raw JSON (or error) as a tool result. On
// error the SDK marks the result IsError and surfaces the message to the model
// so it can self-correct.
func toolResult(raw json.RawMessage, err error) (*mcp.CallToolResult, any, error) {
	if err != nil {
		return nil, nil, err
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: string(raw)}},
	}, nil, nil
}

// --- tool input schemas ---

type emptyInput struct{}

type diagInput struct {
	WithIPv6        bool   `json:"with_ipv6,omitempty" jsonschema:"include IPv6 route candidates"`
	InterfacePrefix string `json:"interface_prefix,omitempty" jsonschema:"interface name prefix to match (default: ligolo)"`
}

type planInput struct {
	WithIPv6        bool   `json:"with_ipv6,omitempty" jsonschema:"include IPv6 route candidates"`
	InterfacePrefix string `json:"interface_prefix,omitempty" jsonschema:"interface name prefix to match (default: ligolo)"`
	Start           bool   `json:"start,omitempty" jsonschema:"include tunnel-start actions in the dry-run plan"`
}

type repairInput struct {
	WithIPv6        bool   `json:"with_ipv6,omitempty" jsonschema:"include IPv6 route candidates"`
	InterfacePrefix string `json:"interface_prefix,omitempty" jsonschema:"interface name prefix to match (default: ligolo)"`
	Start           bool   `json:"start,omitempty" jsonschema:"include or apply tunnel-start actions"`
	PruneConflicts  bool   `json:"prune_conflicts,omitempty" jsonschema:"remove configured lower-ranked duplicate routes"`
}

type failoverPlanInput struct {
	IncludeCommands bool `json:"include_commands,omitempty" jsonschema:"include downstream reconnect commands containing relay tokens"`
}

type failoverApplyInput struct {
	IncludeCommands bool     `json:"include_commands,omitempty" jsonschema:"include downstream reconnect commands containing relay tokens"`
	All             bool     `json:"all,omitempty" jsonschema:"apply every supported failover recommendation"`
	SessionIDs      []string `json:"session_ids,omitempty" jsonschema:"specific downstream SessionIDs to fail over"`
	AgentIDs        []int    `json:"agent_ids,omitempty" jsonschema:"specific agent IDs to fail over"`
}

type autohealRunInput struct {
	Apply            *bool   `json:"apply,omitempty" jsonschema:"apply supported repair and failover actions (omit or false for dry-run)"`
	WithIPv6         *bool   `json:"with_ipv6,omitempty" jsonschema:"include IPv6 route candidates"`
	InterfacePrefix  *string `json:"interface_prefix,omitempty" jsonschema:"interface name prefix to match (default: ligolo)"`
	StartTunnels     *bool   `json:"start_tunnels,omitempty" jsonschema:"include or apply tunnel-start actions"`
	Repair           *bool   `json:"repair,omitempty" jsonschema:"include repair actions (default: server policy)"`
	PruneConflicts   *bool   `json:"prune_conflicts,omitempty" jsonschema:"remove configured lower-ranked duplicate routes"`
	Failover         *bool   `json:"failover,omitempty" jsonschema:"include failover recommendations (default: server policy)"`
	MaxRepairActions *int    `json:"max_repair_actions,omitempty" jsonschema:"maximum repair actions to attempt this run"`
	MaxFailovers     *int    `json:"max_failovers,omitempty" jsonschema:"maximum failover recommendations to attempt this run"`
}

type autorouteInput struct {
	WithIPv6        bool   `json:"with_ipv6,omitempty" jsonschema:"include IPv6 route candidates"`
	InterfacePrefix string `json:"interface_prefix,omitempty" jsonschema:"interface name prefix to match (default: ligolo)"`
	Start           bool   `json:"start,omitempty" jsonschema:"start tunnels after configuring routes"`
}

type relayStartInput struct {
	AgentID         int    `json:"agent_id" jsonschema:"the agent ID to enable relay mode on (from list_agents)"`
	ListenAddr      string `json:"listen_addr,omitempty" jsonschema:"address:port the agent listens on for downstream agents (default: 127.0.0.1:11602)"`
	AuthToken       string `json:"auth_token,omitempty" jsonschema:"relay auth token; the proxy generates one when empty"`
	TokenTTLSeconds int64  `json:"token_ttl_seconds,omitempty" jsonschema:"relay token lifetime in seconds (default: server default)"`
	OneTimeToken    bool   `json:"one_time_token,omitempty" jsonschema:"allow the token to authenticate one downstream agent only"`
}

type relayTokenInput struct {
	AgentID         int    `json:"agent_id" jsonschema:"the agent ID whose relay token to rotate (from list_agents)"`
	AuthToken       string `json:"auth_token,omitempty" jsonschema:"new relay auth token; the proxy generates one when empty"`
	TokenTTLSeconds int64  `json:"token_ttl_seconds,omitempty" jsonschema:"new relay token lifetime in seconds"`
	OneTimeToken    bool   `json:"one_time_token,omitempty" jsonschema:"allow the token to authenticate one downstream agent only"`
}

type agentInput struct {
	AgentID int `json:"agent_id" jsonschema:"the agent ID (from list_agents)"`
}

type tunnelStartInput struct {
	AgentID   int    `json:"agent_id" jsonschema:"the agent ID to start the tunnel for (from list_agents)"`
	Interface string `json:"interface" jsonschema:"the TUN interface name to bind (e.g. ligolo)"`
}

type listenerCreateInput struct {
	AgentID      int    `json:"agent_id" jsonschema:"the agent ID to create the listener on (from list_agents)"`
	ListenerAddr string `json:"listener_addr" jsonschema:"address:port the agent should listen on"`
	RedirectAddr string `json:"redirect_addr" jsonschema:"local proxy address:port traffic is redirected to"`
	Network      string `json:"network,omitempty" jsonschema:"tcp or udp (default: tcp)"`
}

type listenerDeleteInput struct {
	AgentID    int `json:"agent_id" jsonschema:"the agent ID that owns the listener (from list_listeners)"`
	ListenerID int `json:"listener_id" jsonschema:"the listener ID (from list_listeners)"`
}

type interfaceInput struct {
	Interface string `json:"interface" jsonschema:"the TUN interface name"`
}

type addRouteInput struct {
	Interface string   `json:"interface" jsonschema:"the TUN interface name"`
	Routes    []string `json:"routes" jsonschema:"CIDR networks to route through the interface (e.g. 10.0.0.0/24)"`
}

type deleteRouteInput struct {
	Interface string `json:"interface" jsonschema:"the TUN interface name"`
	Route     string `json:"route" jsonschema:"the CIDR network to remove"`
}

// registerTools wires every backend operation onto the MCP server. Read-only
// tools are always registered; mutating tools are skipped when readOnly is set.
func registerTools(server *mcp.Server, backend RelayBackend, readOnly bool) {
	registerReadTools(server, backend)
	if !readOnly {
		registerWriteTools(server, backend)
	}
}

func registerReadTools(server *mcp.Server, backend RelayBackend) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "ping",
		Description: "Health check the Ligolo-ng Relay proxy API. Returns pong when reachable and authenticated.",
		Annotations: readOnlyAnnotations(),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ emptyInput) (*mcp.CallToolResult, any, error) {
		return toolResult(backend.Ping(ctx))
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "list_agents",
		Description: "List all connected agents with their session IDs, network interfaces, tunnel/relay state, and parent (for relayed agents). Use the returned agent IDs with the other tools.",
		Annotations: readOnlyAnnotations(),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ emptyInput) (*mcp.CallToolResult, any, error) {
		return toolResult(backend.ListAgents(ctx))
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_chains",
		Description: "Show the relay chain topology: which agents are direct vs. relayed, their hop depth, and parent relationships.",
		Annotations: readOnlyAnnotations(),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ emptyInput) (*mcp.CallToolResult, any, error) {
		return toolResult(backend.GetChains(ctx))
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "relay_doctor",
		Description: "Relay health report: relay status, token expiry, recent relay events, and route conflicts/warnings across the chain.",
		Annotations: readOnlyAnnotations(),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in diagInput) (*mcp.CallToolResult, any, error) {
		return toolResult(backend.RelayDoctor(ctx, DiagOptions{WithIPv6: in.WithIPv6, InterfacePrefix: in.InterfacePrefix}))
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "relay_ops",
		Description: "Comprehensive relay operations report: doctor findings plus summary, recommended actions, route plan, mesh health, repair plan, failover plan, and auto-heal status. The best single tool for an overall picture.",
		Annotations: readOnlyAnnotations(),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in diagInput) (*mcp.CallToolResult, any, error) {
		return toolResult(backend.RelayOps(ctx, DiagOptions{WithIPv6: in.WithIPv6, InterfacePrefix: in.InterfacePrefix}))
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "autoheal_status",
		Description: "Show the relay auto-heal reconciler configuration, whether it is enabled, and recent run history.",
		Annotations: readOnlyAnnotations(),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ emptyInput) (*mcp.CallToolResult, any, error) {
		return toolResult(backend.AutohealStatus(ctx))
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "list_chain_routes",
		Description: "List route candidates discovered across every agent in the relay chain, with hop depth, interface, and any conflict warnings.",
		Annotations: readOnlyAnnotations(),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in diagInput) (*mcp.CallToolResult, any, error) {
		return toolResult(backend.ListChainRoutes(ctx, DiagOptions{WithIPv6: in.WithIPv6, InterfacePrefix: in.InterfacePrefix}))
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "chain_route_plan",
		Description: "Dry-run the smart route plan: shows, per route candidate, whether it would be applied or skipped (and why) without changing anything.",
		Annotations: readOnlyAnnotations(),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in planInput) (*mcp.CallToolResult, any, error) {
		return toolResult(backend.ChainRoutePlan(ctx, PlanOptions{WithIPv6: in.WithIPv6, InterfacePrefix: in.InterfacePrefix, Start: in.Start}))
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "chain_repair_plan",
		Description: "Dry-run the repair plan: detected issues and the safe repair actions that would be taken, without applying them. Use chain_repair_apply to execute.",
		Annotations: readOnlyAnnotations(),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in repairInput) (*mcp.CallToolResult, any, error) {
		return toolResult(backend.ChainRepairPlan(ctx, RepairOptions{WithIPv6: in.WithIPv6, InterfacePrefix: in.InterfacePrefix, Start: in.Start, PruneConflicts: in.PruneConflicts}))
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "chain_failover_plan",
		Description: "Dry-run parent failover recommendations for relayed agents: current parent vs. recommended parent and the reason, without applying. Use chain_failover_apply to execute.",
		Annotations: readOnlyAnnotations(),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in failoverPlanInput) (*mcp.CallToolResult, any, error) {
		return toolResult(backend.ChainFailoverPlan(ctx, in.IncludeCommands))
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "list_listeners",
		Description: "List active listeners/redirectors across all agents (listener ID, agent, network, agent listen address, proxy redirect address, status).",
		Annotations: readOnlyAnnotations(),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ emptyInput) (*mcp.CallToolResult, any, error) {
		return toolResult(backend.ListListeners(ctx))
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "list_interfaces",
		Description: "List configured TUN interfaces and their routes and state (pending/active).",
		Annotations: readOnlyAnnotations(),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ emptyInput) (*mcp.CallToolResult, any, error) {
		return toolResult(backend.ListInterfaces(ctx))
	})
}

func registerWriteTools(server *mcp.Server, backend RelayBackend) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "autoheal_run",
		Description: "Run one relay auto-heal reconciliation. By default this is a dry-run; set apply=true to apply supported repair and failover actions. Omitted fields preserve the server's configured policy.",
		Annotations: additiveAnnotations(),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in autohealRunInput) (*mcp.CallToolResult, any, error) {
		return toolResult(backend.AutohealRun(ctx, AutohealRunOptions{
			Apply:            in.Apply,
			WithIPv6:         in.WithIPv6,
			InterfacePrefix:  in.InterfacePrefix,
			StartTunnels:     in.StartTunnels,
			Repair:           in.Repair,
			PruneConflicts:   in.PruneConflicts,
			Failover:         in.Failover,
			MaxRepairActions: in.MaxRepairActions,
			MaxFailovers:     in.MaxFailovers,
		}))
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "chain_autoroute",
		Description: "Apply the smart route plan across the chain: create the needed interfaces and routes (and optionally start tunnels). Changes proxy routing state.",
		Annotations: additiveAnnotations(),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in autorouteInput) (*mcp.CallToolResult, any, error) {
		return toolResult(backend.ChainAutoroute(ctx, AutorouteOptions{WithIPv6: in.WithIPv6, InterfacePrefix: in.InterfacePrefix, Start: in.Start}))
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "chain_repair_apply",
		Description: "Apply the repair plan: execute safe repair actions (ensure routes, start tunnels, optionally prune duplicate routes). Run chain_repair_plan first to preview. May disrupt existing routing.",
		Annotations: destructiveAnnotations(),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in repairInput) (*mcp.CallToolResult, any, error) {
		return toolResult(backend.ChainRepairApply(ctx, RepairOptions{WithIPv6: in.WithIPv6, InterfacePrefix: in.InterfacePrefix, Start: in.Start, PruneConflicts: in.PruneConflicts}))
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "chain_failover_apply",
		Description: "Apply parent failover for relayed agents. Requires all=true, or session_ids, or agent_ids. Re-parents downstream agents onto a healthier relay; disrupts the affected agents' current path. Preview with chain_failover_plan first.",
		Annotations: destructiveAnnotations(),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in failoverApplyInput) (*mcp.CallToolResult, any, error) {
		return toolResult(backend.ChainFailoverApply(ctx, FailoverApplyOptions{
			IncludeCommands: in.IncludeCommands,
			All:             in.All,
			SessionIDs:      in.SessionIDs,
			AgentIDs:        in.AgentIDs,
		}))
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "relay_start",
		Description: "Enable relay mode on an agent so downstream agents can connect through it. Returns the certificate fingerprint, auth token, expiry, and the downstream connect command.",
		Annotations: additiveAnnotations(),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in relayStartInput) (*mcp.CallToolResult, any, error) {
		return toolResult(backend.RelayStart(ctx, in.AgentID, RelayStartOptions{
			ListenAddr:      in.ListenAddr,
			AuthToken:       in.AuthToken,
			TokenTTLSeconds: in.TokenTTLSeconds,
			OneTimeToken:    in.OneTimeToken,
		}))
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "relay_stop",
		Description: "Stop relay mode on an agent. Disconnects any downstream agents currently relayed through it.",
		Annotations: destructiveIdempotentAnnotations(),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in agentInput) (*mcp.CallToolResult, any, error) {
		return toolResult(backend.RelayStop(ctx, in.AgentID))
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "relay_token_rotate",
		Description: "Rotate the relay auth token on an agent by restarting its relay listener with a new token. Existing downstream agents must reconnect with the new token.",
		Annotations: additiveAnnotations(),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in relayTokenInput) (*mcp.CallToolResult, any, error) {
		return toolResult(backend.RelayTokenRotate(ctx, in.AgentID, RelayTokenOptions{
			AuthToken:       in.AuthToken,
			TokenTTLSeconds: in.TokenTTLSeconds,
			OneTimeToken:    in.OneTimeToken,
		}))
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "relay_token_revoke",
		Description: "Revoke the relay auth token on an agent and stop relay mode. Disconnects downstream agents.",
		Annotations: destructiveIdempotentAnnotations(),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in agentInput) (*mcp.CallToolResult, any, error) {
		return toolResult(backend.RelayTokenRevoke(ctx, in.AgentID))
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "tunnel_start",
		Description: "Start the TUN tunnel for an agent, binding the given interface so its networks become reachable.",
		Annotations: additiveAnnotations(),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in tunnelStartInput) (*mcp.CallToolResult, any, error) {
		return toolResult(backend.TunnelStart(ctx, in.AgentID, in.Interface))
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "tunnel_stop",
		Description: "Stop the TUN tunnel for an agent. The agent's networks become unreachable until restarted.",
		Annotations: destructiveIdempotentAnnotations(),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in agentInput) (*mcp.CallToolResult, any, error) {
		return toolResult(backend.TunnelStop(ctx, in.AgentID))
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "create_listener",
		Description: "Create a listener/redirector on an agent: the agent listens on listener_addr and traffic is redirected to redirect_addr on the proxy side.",
		Annotations: additiveAnnotations(),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in listenerCreateInput) (*mcp.CallToolResult, any, error) {
		network := in.Network
		if network == "" {
			network = "tcp"
		}
		return toolResult(backend.CreateListener(ctx, ListenerOptions{
			AgentID:      in.AgentID,
			ListenerAddr: in.ListenerAddr,
			RedirectAddr: in.RedirectAddr,
			Network:      network,
		}))
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "delete_listener",
		Description: "Delete a listener from an agent by agent ID and listener ID (see list_listeners).",
		Annotations: destructiveAnnotations(),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in listenerDeleteInput) (*mcp.CallToolResult, any, error) {
		return toolResult(backend.DeleteListener(ctx, in.AgentID, in.ListenerID))
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "create_interface",
		Description: "Create a TUN interface (created immediately on supported platforms, otherwise on tunnel start).",
		Annotations: additiveAnnotations(),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in interfaceInput) (*mcp.CallToolResult, any, error) {
		return toolResult(backend.CreateInterface(ctx, in.Interface))
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "delete_interface",
		Description: "Delete a TUN interface and its configuration. Routes through it are removed.",
		Annotations: destructiveAnnotations(),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in interfaceInput) (*mcp.CallToolResult, any, error) {
		return toolResult(backend.DeleteInterface(ctx, in.Interface))
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "add_route",
		Description: "Add one or more CIDR routes to a TUN interface (applied immediately if the interface exists, otherwise on tunnel start).",
		Annotations: additiveAnnotations(),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in addRouteInput) (*mcp.CallToolResult, any, error) {
		return toolResult(backend.AddRoute(ctx, in.Interface, in.Routes))
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "delete_route",
		Description: "Remove a CIDR route from a TUN interface.",
		Annotations: destructiveAnnotations(),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in deleteRouteInput) (*mcp.CallToolResult, any, error) {
		return toolResult(backend.DeleteRoute(ctx, in.Interface, in.Route))
	})
}
