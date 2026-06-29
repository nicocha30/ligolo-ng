// Ligolo-ng Relay
// Copyright (C) 2025 Nicolas Chatelain (nicocha30)

package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/allsmog/ligolo-ng-relay/cmd/proxy/config"
	"github.com/allsmog/ligolo-ng-relay/pkg/controller"
	"github.com/allsmog/ligolo-ng-relay/pkg/proxy/netinfo"
	"github.com/allsmog/ligolo-ng-relay/pkg/relaymcp"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/sirupsen/logrus"
)

// MCPServerVersion is the version the embedded MCP server reports to clients.
// The proxy's main sets it from the build stamp.
var MCPServerVersion = "dev"

// RunMCPStdio runs the in-process MCP server over stdio until ctx is cancelled
// or the client disconnects. The proxy keeps listening for agents in the
// background; this is just the operator-facing frontend (in place of the CLI).
func RunMCPStdio(ctx context.Context, readOnly bool) error {
	server := relaymcp.NewMCPServer(inProcBackend{}, relaymcp.ServerOptions{
		ReadOnly: readOnly,
		Version:  MCPServerVersion,
	})
	return server.Run(ctx, &mcp.StdioTransport{})
}

// NewMCPHTTPHandler returns a streamable-HTTP MCP handler backed by the
// in-process state, for mounting on the existing API server.
func NewMCPHTTPHandler(readOnly bool) http.Handler {
	server := relaymcp.NewMCPServer(inProcBackend{}, relaymcp.ServerOptions{
		ReadOnly: readOnly,
		Version:  MCPServerVersion,
	})
	return mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server {
		return server
	}, nil)
}

// inProcBackend implements relaymcp.RelayBackend by calling the same app/config
// primitives the REST (Gin) handlers use, marshaling their results to JSON.
// It is a thin adapter — the real logic lives in the shared functions — so the
// embedded MCP server and the REST API stay behaviorally identical.
type inProcBackend struct{}

func marshalJSON(v any) (json.RawMessage, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func mcpInterfacePrefix(prefix string) string {
	if prefix == "" {
		return "ligolo"
	}
	return prefix
}

func lookupAgent(agentID int) (*controller.LigoloAgent, bool) {
	AgentListMutex.Lock()
	defer AgentListMutex.Unlock()
	agent, ok := AgentList[agentID]
	return agent, ok
}

// --- Read-only ---

func (inProcBackend) Ping(context.Context) (json.RawMessage, error) {
	return marshalJSON(map[string]string{"message": "pong"})
}

func (inProcBackend) ListAgents(context.Context) (json.RawMessage, error) {
	AgentListMutex.Lock()
	defer AgentListMutex.Unlock()
	return marshalJSON(AgentList)
}

func (inProcBackend) GetChains(context.Context) (json.RawMessage, error) {
	return marshalJSON(chainSnapshot())
}

func (inProcBackend) RelayDoctor(_ context.Context, o relaymcp.DiagOptions) (json.RawMessage, error) {
	return marshalJSON(relayDoctorReport(o.WithIPv6, mcpInterfacePrefix(o.InterfacePrefix)))
}

func (inProcBackend) RelayOps(_ context.Context, o relaymcp.DiagOptions) (json.RawMessage, error) {
	return marshalJSON(relayOpsReport(o.WithIPv6, mcpInterfacePrefix(o.InterfacePrefix)))
}

func (inProcBackend) AutohealStatus(context.Context) (json.RawMessage, error) {
	return marshalJSON(RelayAutoHealStatusSnapshot())
}

func (inProcBackend) ListChainRoutes(_ context.Context, o relaymcp.DiagOptions) (json.RawMessage, error) {
	return marshalJSON(map[string]any{"routes": chainRouteInfos(o.WithIPv6, mcpInterfacePrefix(o.InterfacePrefix))})
}

func (inProcBackend) ChainRoutePlan(_ context.Context, o relaymcp.PlanOptions) (json.RawMessage, error) {
	return marshalJSON(chainRoutePlan(o.WithIPv6, mcpInterfacePrefix(o.InterfacePrefix), o.Start))
}

func (inProcBackend) ChainRepairPlan(_ context.Context, o relaymcp.RepairOptions) (json.RawMessage, error) {
	return marshalJSON(chainRepairPlan(o.WithIPv6, mcpInterfacePrefix(o.InterfacePrefix), o.Start, o.PruneConflicts))
}

func (inProcBackend) ChainFailoverPlan(_ context.Context, includeCommands bool) (json.RawMessage, error) {
	return marshalJSON(chainFailoverPlan(includeCommands))
}

func (inProcBackend) ListListeners(context.Context) (json.RawMessage, error) {
	type listenerInfo struct {
		ListenerID   int32
		AgentID      int
		Agent        string
		RemoteAddr   string
		SessionID    string
		Network      string
		ListenerAddr string
		RedirectAddr string
		Online       bool
	}
	AgentListMutex.Lock()
	defer AgentListMutex.Unlock()
	var listeners []listenerInfo
	for agentID, agent := range AgentList {
		for _, listener := range agent.Listeners {
			listeners = append(listeners, listenerInfo{
				ListenerID:   listener.ID,
				Agent:        agent.Name,
				AgentID:      agentID,
				RemoteAddr:   agent.Session.RemoteAddr().String(),
				SessionID:    agent.SessionID,
				Network:      listener.Network(),
				ListenerAddr: listener.ListenerAddr(),
				RedirectAddr: listener.RedirectAddr(),
				Online:       agent.Alive(),
			})
		}
	}
	return marshalJSON(listeners)
}

func (inProcBackend) ListInterfaces(context.Context) (json.RawMessage, error) {
	interfaces, err := config.GetInterfaceConfigState()
	if err != nil {
		return nil, err
	}
	return marshalJSON(interfaces)
}

// --- Mutating ---

func (inProcBackend) AutohealRun(_ context.Context, o relaymcp.AutohealRunOptions) (json.RawMessage, error) {
	req := RelayAutoHealRunRequest{
		Apply:            o.Apply,
		WithIPv6:         o.WithIPv6,
		InterfacePrefix:  o.InterfacePrefix,
		StartTunnels:     o.StartTunnels,
		Repair:           o.Repair,
		PruneConflicts:   o.PruneConflicts,
		Failover:         o.Failover,
		MaxRepairActions: o.MaxRepairActions,
		MaxFailovers:     o.MaxFailovers,
	}
	policy := relayAutoHealPolicyWithOverrides(relayAutoHealPolicyFromConfig(), req)
	return marshalJSON(RunRelayAutoHealOnce(policy))
}

func (inProcBackend) ChainAutoroute(_ context.Context, o relaymcp.AutorouteOptions) (json.RawMessage, error) {
	prefix := mcpInterfacePrefix(o.InterfacePrefix)
	routes, err := configureChainAutoroutes(o.WithIPv6, prefix, o.Start)
	if err != nil {
		return nil, err
	}
	return marshalJSON(map[string]any{
		"message": "chain autoroute configured",
		"routes":  routes,
		"plan":    chainRoutePlan(o.WithIPv6, prefix, o.Start),
	})
}

func (inProcBackend) ChainRepairApply(_ context.Context, o relaymcp.RepairOptions) (json.RawMessage, error) {
	return marshalJSON(applyChainRepairPlan(o.WithIPv6, mcpInterfacePrefix(o.InterfacePrefix), o.Start, o.PruneConflicts))
}

func (inProcBackend) ChainFailoverApply(_ context.Context, o relaymcp.FailoverApplyOptions) (json.RawMessage, error) {
	if !o.All && len(o.SessionIDs) == 0 && len(o.AgentIDs) == 0 {
		return nil, errors.New("chain failover apply requires All, SessionIDs, or AgentIDs")
	}
	return marshalJSON(applyChainFailoverPlan(o.IncludeCommands, o.All, o.SessionIDs, o.AgentIDs))
}

func (inProcBackend) RelayStart(_ context.Context, agentID int, o relaymcp.RelayStartOptions) (json.RawMessage, error) {
	agent, ok := lookupAgent(agentID)
	if !ok {
		return nil, errors.New("invalid agent")
	}
	if !agent.RelayCapable {
		return nil, errors.New("agent does not support relay mode")
	}
	result, err := startRelayOnAgent(agent, o.ListenAddr, o.AuthToken, relayTokenTTLFromSeconds(o.TokenTTLSeconds), o.OneTimeToken)
	if err != nil {
		return nil, err
	}
	return marshalJSON(map[string]any{
		"message":          "relay started",
		"fingerprint":      result.CertFingerprint,
		"auth_token":       result.AuthToken,
		"token_expires_at": result.TokenExpiresAt,
		"one_time_token":   result.OneTimeToken,
		"connect_command":  relayConnectCommand(o.ListenAddr, result.CertFingerprint, result.AuthToken),
	})
}

func (inProcBackend) RelayStop(_ context.Context, agentID int) (json.RawMessage, error) {
	agent, ok := lookupAgent(agentID)
	if !ok {
		return nil, errors.New("invalid agent")
	}
	if err := stopRelayWithDownstream(agent); err != nil {
		return nil, err
	}
	return marshalJSON(map[string]string{"message": "relay stopped"})
}

func (inProcBackend) RelayTokenRotate(_ context.Context, agentID int, o relaymcp.RelayTokenOptions) (json.RawMessage, error) {
	agent, ok := lookupAgent(agentID)
	if !ok {
		return nil, errors.New("invalid agent")
	}
	result, err := rotateRelayToken(agent, o.AuthToken, relayTokenTTLFromSeconds(o.TokenTTLSeconds), o.OneTimeToken)
	if err != nil {
		return nil, err
	}
	return marshalJSON(map[string]any{
		"message":          "relay token rotated",
		"fingerprint":      result.CertFingerprint,
		"auth_token":       result.AuthToken,
		"token_expires_at": result.TokenExpiresAt,
		"one_time_token":   result.OneTimeToken,
		"connect_command":  relayConnectCommand(agent.RelayListenAddr, result.CertFingerprint, result.AuthToken),
	})
}

func (inProcBackend) RelayTokenRevoke(_ context.Context, agentID int) (json.RawMessage, error) {
	agent, ok := lookupAgent(agentID)
	if !ok {
		return nil, errors.New("invalid agent")
	}
	if err := stopRelayWithDownstream(agent); err != nil {
		return nil, err
	}
	return marshalJSON(map[string]string{"message": "relay token revoked and relay stopped"})
}

func (inProcBackend) TunnelStart(_ context.Context, agentID int, iface string) (json.RawMessage, error) {
	agent, ok := lookupAgent(agentID)
	if !ok {
		return nil, errors.New("invalid agent")
	}
	if err := StartTunnel(agent, iface); err != nil {
		return nil, err
	}
	return marshalJSON(map[string]string{"message": "tunnel starting"})
}

func (inProcBackend) TunnelStop(_ context.Context, agentID int) (json.RawMessage, error) {
	agent, ok := lookupAgent(agentID)
	if !ok {
		return nil, errors.New("invalid agent")
	}
	if agent.Session == nil || !agent.Running {
		return nil, errors.New("tunnel not started")
	}
	agent.CloseChan <- true
	agent.Running = false
	return marshalJSON(map[string]string{"message": "tunnel stopping"})
}

func (inProcBackend) CreateListener(_ context.Context, o relaymcp.ListenerOptions) (json.RawMessage, error) {
	agent, ok := lookupAgent(o.AgentID)
	if !ok {
		return nil, errors.New("invalid agent")
	}
	proxyListener, err := agent.AddListener(o.ListenerAddr, o.Network, o.RedirectAddr)
	if err != nil {
		return nil, err
	}
	go func() {
		if err := proxyListener.StartRelay(); err != nil {
			logrus.WithFields(logrus.Fields{"listener": proxyListener.String(), "agent": agent.Name, "id": agent.SessionID}).Error("Listener relay failed with error: ", err)
			return
		}
		logrus.WithFields(logrus.Fields{"listener": proxyListener.String(), "agent": agent.Name, "id": agent.SessionID}).Warning("Listener ended without error.")
	}()
	return marshalJSON(map[string]string{"message": "listener created"})
}

func (inProcBackend) DeleteListener(_ context.Context, agentID, listenerID int) (json.RawMessage, error) {
	agent, ok := lookupAgent(agentID)
	if !ok {
		return nil, errors.New("invalid agent")
	}
	agent.DeleteListener(listenerID)
	return marshalJSON(map[string]string{"message": "listener deleted"})
}

func (inProcBackend) CreateInterface(_ context.Context, name string) (json.RawMessage, error) {
	if err := config.AddInterfaceConfig(name); err != nil {
		return nil, err
	}
	if netinfo.CanCreateTUNs() {
		if err := netinfo.CreateTUN(name); err != nil {
			return nil, err
		}
		return marshalJSON(map[string]string{"message": fmt.Sprintf("Interface %s created.", name)})
	}
	return marshalJSON(map[string]string{"message": fmt.Sprintf("Interface will %s be created on tunnel start.", name)})
}

func (inProcBackend) DeleteInterface(_ context.Context, name string) (json.RawMessage, error) {
	if err := config.DeleteInterfaceConfig(name); err != nil {
		return nil, err
	}
	if netinfo.InterfaceExist(name) {
		stun, err := netinfo.GetTunByName(name)
		if err != nil {
			return nil, err
		}
		if err := stun.Destroy(); err != nil {
			return nil, err
		}
	}
	return marshalJSON(map[string]string{"message": "interface deleted"})
}

func (inProcBackend) AddRoute(_ context.Context, iface string, routes []string) (json.RawMessage, error) {
	for _, route := range routes {
		if err := config.AddRouteConfig(iface, route); err != nil {
			return nil, err
		}
	}
	if netinfo.InterfaceExist(iface) {
		stun, err := netinfo.GetTunByName(iface)
		if err != nil {
			return nil, err
		}
		for _, route := range routes {
			if err := stun.AddRoute(route); err != nil {
				return nil, err
			}
		}
		return marshalJSON(map[string]string{"message": fmt.Sprintf("Routes %s added.", routes)})
	}
	return marshalJSON(map[string]string{"message": fmt.Sprintf("Routes %s will be created on tunnel start.", routes)})
}

func (inProcBackend) DeleteRoute(_ context.Context, iface, route string) (json.RawMessage, error) {
	if err := config.DeleteRouteConfig(iface, route); err != nil {
		return nil, err
	}
	if netinfo.InterfaceExist(iface) {
		stun, err := netinfo.GetTunByName(iface)
		if err != nil {
			return nil, err
		}
		if err := stun.DelRoute(route); err != nil {
			return nil, err
		}
		return marshalJSON(map[string]string{"message": fmt.Sprintf("Route %s deleted.", route)})
	}
	return nil, fmt.Errorf("Route %s does not exist.", route)
}
