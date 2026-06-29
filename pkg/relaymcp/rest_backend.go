// Ligolo-ng Relay
// Copyright (C) 2025 Nicolas Chatelain (nicocha30)

package relaymcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"

	"github.com/allsmog/ligolo-ng-relay/pkg/relayapi"
)

// defaultInterfacePrefix matches the proxy API's own default for the
// interface_prefix query/body parameter.
const defaultInterfacePrefix = "ligolo"

// RESTBackend implements RelayBackend by calling the proxy REST API through a
// relayapi.Client. It is the backend used by the standalone relaymcp binary.
type RESTBackend struct {
	client *relayapi.Client
}

// NewRESTBackend wraps a relayapi.Client as a RelayBackend.
func NewRESTBackend(client *relayapi.Client) *RESTBackend {
	return &RESTBackend{client: client}
}

func interfacePrefixOrDefault(prefix string) string {
	if prefix == "" {
		return defaultInterfacePrefix
	}
	return prefix
}

func diagQuery(opts DiagOptions) url.Values {
	q := url.Values{}
	q.Set("with_ipv6", strconv.FormatBool(opts.WithIPv6))
	q.Set("interface_prefix", interfacePrefixOrDefault(opts.InterfacePrefix))
	return q
}

// --- Read-only / diagnostics ---

func (b *RESTBackend) Ping(ctx context.Context) (json.RawMessage, error) {
	return b.client.Do(ctx, "GET", "/api/v1/ping", nil)
}

func (b *RESTBackend) ListAgents(ctx context.Context) (json.RawMessage, error) {
	return b.client.Do(ctx, "GET", "/api/v1/agents", nil)
}

func (b *RESTBackend) GetChains(ctx context.Context) (json.RawMessage, error) {
	return b.client.Do(ctx, "GET", "/api/v1/chains", nil)
}

func (b *RESTBackend) RelayDoctor(ctx context.Context, opts DiagOptions) (json.RawMessage, error) {
	return b.client.Do(ctx, "GET", "/api/v1/relay/doctor?"+diagQuery(opts).Encode(), nil)
}

func (b *RESTBackend) RelayOps(ctx context.Context, opts DiagOptions) (json.RawMessage, error) {
	return b.client.Do(ctx, "GET", "/api/v1/relay/ops?"+diagQuery(opts).Encode(), nil)
}

func (b *RESTBackend) AutohealStatus(ctx context.Context) (json.RawMessage, error) {
	return b.client.Do(ctx, "GET", "/api/v1/relay/autoheal", nil)
}

func (b *RESTBackend) ListChainRoutes(ctx context.Context, opts DiagOptions) (json.RawMessage, error) {
	return b.client.Do(ctx, "GET", "/api/v1/chain_routes?"+diagQuery(opts).Encode(), nil)
}

func (b *RESTBackend) ChainRoutePlan(ctx context.Context, opts PlanOptions) (json.RawMessage, error) {
	q := url.Values{}
	q.Set("with_ipv6", strconv.FormatBool(opts.WithIPv6))
	q.Set("interface_prefix", interfacePrefixOrDefault(opts.InterfacePrefix))
	q.Set("start", strconv.FormatBool(opts.Start))
	return b.client.Do(ctx, "GET", "/api/v1/chain_route_plan?"+q.Encode(), nil)
}

func (b *RESTBackend) ChainRepairPlan(ctx context.Context, opts RepairOptions) (json.RawMessage, error) {
	q := url.Values{}
	q.Set("with_ipv6", strconv.FormatBool(opts.WithIPv6))
	q.Set("interface_prefix", interfacePrefixOrDefault(opts.InterfacePrefix))
	q.Set("start", strconv.FormatBool(opts.Start))
	q.Set("prune_conflicts", strconv.FormatBool(opts.PruneConflicts))
	return b.client.Do(ctx, "GET", "/api/v1/chain_repair_plan?"+q.Encode(), nil)
}

func (b *RESTBackend) ChainFailoverPlan(ctx context.Context, includeCommands bool) (json.RawMessage, error) {
	q := url.Values{}
	q.Set("include_commands", strconv.FormatBool(includeCommands))
	return b.client.Do(ctx, "GET", "/api/v1/chain_failover_plan?"+q.Encode(), nil)
}

func (b *RESTBackend) ListListeners(ctx context.Context) (json.RawMessage, error) {
	return b.client.Do(ctx, "GET", "/api/v1/listeners", nil)
}

func (b *RESTBackend) ListInterfaces(ctx context.Context) (json.RawMessage, error) {
	return b.client.Do(ctx, "GET", "/api/v1/interfaces", nil)
}

// --- Mutating ---

func (b *RESTBackend) AutohealRun(ctx context.Context, opts AutohealRunOptions) (json.RawMessage, error) {
	// Only include supplied overrides; nil fields preserve the proxy's
	// configured policy (the API uses pointer fields with the same semantics).
	body := map[string]any{}
	if opts.Apply != nil {
		body["Apply"] = *opts.Apply
	}
	if opts.WithIPv6 != nil {
		body["WithIPv6"] = *opts.WithIPv6
	}
	if opts.InterfacePrefix != nil {
		body["InterfacePrefix"] = *opts.InterfacePrefix
	}
	if opts.StartTunnels != nil {
		body["StartTunnels"] = *opts.StartTunnels
	}
	if opts.Repair != nil {
		body["Repair"] = *opts.Repair
	}
	if opts.PruneConflicts != nil {
		body["PruneConflicts"] = *opts.PruneConflicts
	}
	if opts.Failover != nil {
		body["Failover"] = *opts.Failover
	}
	if opts.MaxRepairActions != nil {
		body["MaxRepairActions"] = *opts.MaxRepairActions
	}
	if opts.MaxFailovers != nil {
		body["MaxFailovers"] = *opts.MaxFailovers
	}
	return b.client.Do(ctx, "POST", "/api/v1/relay/autoheal/run", body)
}

func (b *RESTBackend) ChainAutoroute(ctx context.Context, opts AutorouteOptions) (json.RawMessage, error) {
	return b.client.Do(ctx, "POST", "/api/v1/chain_autoroute", map[string]any{
		"WithIPv6":        opts.WithIPv6,
		"InterfacePrefix": interfacePrefixOrDefault(opts.InterfacePrefix),
		"Start":           opts.Start,
	})
}

func (b *RESTBackend) ChainRepairApply(ctx context.Context, opts RepairOptions) (json.RawMessage, error) {
	return b.client.Do(ctx, "POST", "/api/v1/chain_repair", map[string]any{
		"WithIPv6":        opts.WithIPv6,
		"InterfacePrefix": interfacePrefixOrDefault(opts.InterfacePrefix),
		"Start":           opts.Start,
		"PruneConflicts":  opts.PruneConflicts,
	})
}

func (b *RESTBackend) ChainFailoverApply(ctx context.Context, opts FailoverApplyOptions) (json.RawMessage, error) {
	return b.client.Do(ctx, "POST", "/api/v1/chain_failover", map[string]any{
		"IncludeCommands": opts.IncludeCommands,
		"All":             opts.All,
		"SessionIDs":      opts.SessionIDs,
		"AgentIDs":        opts.AgentIDs,
	})
}

func (b *RESTBackend) RelayStart(ctx context.Context, agentID int, opts RelayStartOptions) (json.RawMessage, error) {
	return b.client.Do(ctx, "POST", fmt.Sprintf("/api/v1/relay/%d", agentID), map[string]any{
		"ListenAddr":      opts.ListenAddr,
		"AuthToken":       opts.AuthToken,
		"TokenTTLSeconds": opts.TokenTTLSeconds,
		"OneTimeToken":    opts.OneTimeToken,
	})
}

func (b *RESTBackend) RelayStop(ctx context.Context, agentID int) (json.RawMessage, error) {
	return b.client.Do(ctx, "DELETE", fmt.Sprintf("/api/v1/relay/%d", agentID), nil)
}

func (b *RESTBackend) RelayTokenRotate(ctx context.Context, agentID int, opts RelayTokenOptions) (json.RawMessage, error) {
	return b.client.Do(ctx, "POST", fmt.Sprintf("/api/v1/relay/%d/token", agentID), map[string]any{
		"AuthToken":       opts.AuthToken,
		"TokenTTLSeconds": opts.TokenTTLSeconds,
		"OneTimeToken":    opts.OneTimeToken,
	})
}

func (b *RESTBackend) RelayTokenRevoke(ctx context.Context, agentID int) (json.RawMessage, error) {
	return b.client.Do(ctx, "DELETE", fmt.Sprintf("/api/v1/relay/%d/token", agentID), nil)
}

func (b *RESTBackend) TunnelStart(ctx context.Context, agentID int, iface string) (json.RawMessage, error) {
	return b.client.Do(ctx, "POST", fmt.Sprintf("/api/v1/tunnel/%d", agentID), map[string]any{
		"Interface": iface,
	})
}

func (b *RESTBackend) TunnelStop(ctx context.Context, agentID int) (json.RawMessage, error) {
	return b.client.Do(ctx, "DELETE", fmt.Sprintf("/api/v1/tunnel/%d", agentID), nil)
}

func (b *RESTBackend) CreateListener(ctx context.Context, opts ListenerOptions) (json.RawMessage, error) {
	return b.client.Do(ctx, "POST", "/api/v1/listeners", map[string]any{
		"AgentID":      opts.AgentID,
		"ListenerAddr": opts.ListenerAddr,
		"RedirectAddr": opts.RedirectAddr,
		"Network":      opts.Network,
	})
}

func (b *RESTBackend) DeleteListener(ctx context.Context, agentID, listenerID int) (json.RawMessage, error) {
	return b.client.Do(ctx, "DELETE", "/api/v1/listeners", map[string]any{
		"ListenerID": listenerID,
		"AgentID":    agentID,
	})
}

func (b *RESTBackend) CreateInterface(ctx context.Context, name string) (json.RawMessage, error) {
	return b.client.Do(ctx, "POST", "/api/v1/interfaces", map[string]any{
		"Interface": name,
	})
}

func (b *RESTBackend) DeleteInterface(ctx context.Context, name string) (json.RawMessage, error) {
	return b.client.Do(ctx, "DELETE", "/api/v1/interfaces", map[string]any{
		"Interface": name,
	})
}

func (b *RESTBackend) AddRoute(ctx context.Context, iface string, routes []string) (json.RawMessage, error) {
	return b.client.Do(ctx, "POST", "/api/v1/routes", map[string]any{
		"Interface": iface,
		"Route":     routes,
	})
}

func (b *RESTBackend) DeleteRoute(ctx context.Context, iface, route string) (json.RawMessage, error) {
	return b.client.Do(ctx, "DELETE", "/api/v1/routes", map[string]any{
		"Interface": iface,
		"Route":     route,
	})
}
