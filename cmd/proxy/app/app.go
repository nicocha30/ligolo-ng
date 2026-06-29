// Ligolo-ng Relay
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

package app

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/allsmog/ligolo-ng-relay/cmd/proxy/config"
	"github.com/allsmog/ligolo-ng-relay/pkg/proxy/netinfo"
	"net"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/AlecAivazis/survey/v2"
	"github.com/allsmog/ligolo-ng-relay/pkg/controller"
	"github.com/allsmog/ligolo-ng-relay/pkg/proxy"
	"github.com/allsmog/ligolo-ng-relay/pkg/proxy/netstack"
	"github.com/desertbit/grumble"
	"github.com/hashicorp/yamux"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/sirupsen/logrus"
)

var AgentList map[int]*controller.LigoloAgent
var AgentListMutex sync.Mutex
var ProxyController *controller.Controller
var ChainMgr = proxy.NewChainManager()

// CurrentAgentID points to the selected agent in the UI (when running session)
var CurrentAgentID int

// Store AgentIDs
var AgentCounter int

var (
	ErrInvalidAgent   = errors.New("please, select an agent using the session command")
	ErrAlreadyRunning = errors.New("already running")
	ErrNotRunning     = errors.New("no tunnel started")
)

const (
	pathRTTProbeTimeout = 1500 * time.Millisecond
	pathRTTCacheTTL     = 5 * time.Second
)

type pathRTTCacheEntry struct {
	value     *int64
	checkedAt time.Time
}

var pathRTTCache = struct {
	sync.Mutex
	entries map[string]pathRTTCacheEntry
}{
	entries: make(map[string]pathRTTCacheEntry),
}

func cloneInt64(value *int64) *int64 {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func chainAgentInfos() []proxy.AgentInfo {
	AgentListMutex.Lock()

	ids := make([]int, 0, len(AgentList))
	for agentID := range AgentList {
		ids = append(ids, agentID)
	}
	sort.Ints(ids)

	type chainAgentEntry struct {
		info  proxy.AgentInfo
		agent *controller.LigoloAgent
	}
	entries := make([]chainAgentEntry, 0, len(ids))
	for _, agentID := range ids {
		agent := AgentList[agentID]
		relayStatus := agent.RelayStatusSnapshot()
		remoteAddr := ""
		if agent.Session != nil {
			remoteAddr = agent.Session.RemoteAddr().String()
		}
		entries = append(entries, chainAgentEntry{
			agent: agent,
			info: proxy.AgentInfo{
				AgentID:              agentID,
				Name:                 agent.Name,
				SessionID:            agent.SessionID,
				RemoteAddr:           remoteAddr,
				RelayActive:          agent.RelayActive,
				RelayListenAddr:      agent.RelayListenAddr,
				RelayCertFingerprint: relayStatus.CertFingerprint,
				RelayTokenExpiresAt:  relayStatus.TokenExpiresAt,
				RelayTokenExpired:    relayStatus.TokenExpired,
				RelayOneTimeToken:    relayStatus.OneTimeToken,
				Alive:                agent.Alive(),
				Running:              agent.Running,
				ParentSessionID:      agent.ParentAgentID,
			},
		})
	}
	AgentListMutex.Unlock()

	type pathRTTProbe struct {
		index     int
		sessionID string
		agent     *controller.LigoloAgent
	}
	type pathRTTProbeResult struct {
		index     int
		sessionID string
		value     *int64
	}

	now := time.Now()
	agents := make([]proxy.AgentInfo, len(entries))
	probes := make([]pathRTTProbe, 0, len(entries))

	pathRTTCache.Lock()
	for index, entry := range entries {
		info := entry.info
		if info.SessionID == "" {
			agents[index] = info
			continue
		}
		if !info.Alive {
			delete(pathRTTCache.entries, info.SessionID)
			agents[index] = info
			continue
		}
		if cached, ok := pathRTTCache.entries[info.SessionID]; ok && now.Sub(cached.checkedAt) < pathRTTCacheTTL {
			info.PathRTTMS = cloneInt64(cached.value)
		} else {
			probes = append(probes, pathRTTProbe{
				index:     index,
				sessionID: info.SessionID,
				agent:     entry.agent,
			})
		}
		agents[index] = info
	}
	pathRTTCache.Unlock()

	if len(probes) == 0 {
		return agents
	}

	results := make(chan pathRTTProbeResult, len(probes))
	var wg sync.WaitGroup
	for _, probe := range probes {
		wg.Add(1)
		go func(probe pathRTTProbe) {
			defer wg.Done()
			var pathRTTMS *int64
			if pathRTT, err := probe.agent.ProbePathRTT(pathRTTProbeTimeout); err == nil {
				value := pathRTT.Milliseconds()
				pathRTTMS = &value
			}
			results <- pathRTTProbeResult{
				index:     probe.index,
				sessionID: probe.sessionID,
				value:     pathRTTMS,
			}
		}(probe)
	}
	wg.Wait()
	close(results)

	pathRTTCache.Lock()
	for result := range results {
		agents[result.index].PathRTTMS = cloneInt64(result.value)
		pathRTTCache.entries[result.sessionID] = pathRTTCacheEntry{
			value:     cloneInt64(result.value),
			checkedAt: time.Now(),
		}
	}
	pathRTTCache.Unlock()

	return agents
}

func chainSnapshot() proxy.ChainSnapshot {
	return ChainMgr.Snapshot(chainAgentInfos())
}

type ChainRouteInfo struct {
	AgentID         int    `json:"agent_id"`
	Name            string `json:"name"`
	SessionID       string `json:"session_id"`
	ParentSessionID string `json:"parent_session_id"`
	HopDepth        int    `json:"hop_depth"`
	Interface       string `json:"interface"`
	Route           string `json:"route"`
	Conflict        bool   `json:"conflict"`
	ConflictWith    []int  `json:"conflict_with,omitempty"`
	Warning         string `json:"warning,omitempty"`
}

func candidateRoutes(agent *controller.LigoloAgent, includeIPv6 bool) []string {
	var routes []string
	for _, ifaceInfo := range agent.Network {
		for _, address := range ifaceInfo.Addresses {
			ip, _, err := net.ParseCIDR(address)
			if err != nil {
				continue
			}
			if ip.IsLoopback() {
				continue
			}
			if ip.To4() != nil || includeIPv6 {
				routes = append(routes, address)
			}
		}
	}
	sort.Strings(routes)
	return routes
}

func chainInterfaceName(prefix string, agentID int) string {
	if prefix == "" {
		prefix = "ligolo"
	}
	return fmt.Sprintf("%s%d", prefix, agentID)
}

func routeConflictKey(route string) string {
	ip, ipNet, err := net.ParseCIDR(route)
	if err != nil {
		return route
	}
	ipNet.IP = ip.Mask(ipNet.Mask)
	return ipNet.String()
}

func chainRouteInfos(includeIPv6 bool, interfacePrefix string) []ChainRouteInfo {
	AgentListMutex.Lock()
	ids := make([]int, 0, len(AgentList))
	for agentID := range AgentList {
		ids = append(ids, agentID)
	}
	sort.Ints(ids)

	agents := make(map[int]*controller.LigoloAgent, len(AgentList))
	for _, agentID := range ids {
		agents[agentID] = AgentList[agentID]
	}
	AgentListMutex.Unlock()

	var routes []ChainRouteInfo
	for _, agentID := range ids {
		agent := agents[agentID]
		if agent == nil || !agent.Alive() {
			continue
		}
		for _, route := range candidateRoutes(agent, includeIPv6) {
			routes = append(routes, ChainRouteInfo{
				AgentID:         agentID,
				Name:            agent.Name,
				SessionID:       agent.SessionID,
				ParentSessionID: agent.ParentAgentID,
				HopDepth:        ChainMgr.GetChainDepth(agent.SessionID),
				Interface:       chainInterfaceName(interfacePrefix, agentID),
				Route:           route,
			})
		}
	}
	routesByCIDR := make(map[string][]int)
	for _, route := range routes {
		key := routeConflictKey(route.Route)
		routesByCIDR[key] = append(routesByCIDR[key], route.AgentID)
	}
	for i := range routes {
		key := routeConflictKey(routes[i].Route)
		agentIDs := routesByCIDR[key]
		if len(agentIDs) <= 1 {
			continue
		}
		routes[i].Conflict = true
		for _, agentID := range agentIDs {
			if agentID != routes[i].AgentID {
				routes[i].ConflictWith = append(routes[i].ConflictWith, agentID)
			}
		}
		routes[i].Warning = fmt.Sprintf("route %s is advertised by multiple agents", key)
	}
	return routes
}

func configureChainAutoroutes(includeIPv6 bool, interfacePrefix string, start bool) ([]ChainRouteInfo, error) {
	plan := chainRoutePlan(includeIPv6, interfacePrefix, start)
	if len(plan.Decisions) == 0 {
		return nil, errors.New("no route candidates available")
	}

	interfacesByAgent := make(map[int]string)
	var appliedRoutes []ChainRouteInfo
	for _, decision := range plan.Decisions {
		if decision.Decision != routeDecisionApply {
			continue
		}
		interfacesByAgent[decision.AgentID] = decision.Interface
		if err := config.EnsureInterfaceConfig(decision.Interface); err != nil {
			return nil, fmt.Errorf("could not configure interface %s: %w", decision.Interface, err)
		}
		if err := config.EnsureRouteConfig(decision.Interface, decision.Route); err != nil {
			return nil, fmt.Errorf("could not configure route %s on %s: %w", decision.Route, decision.Interface, err)
		}
		appliedRoutes = append(appliedRoutes, ChainRouteInfo{
			AgentID:         decision.AgentID,
			Name:            decision.Name,
			SessionID:       decision.SessionID,
			ParentSessionID: decision.ParentSessionID,
			HopDepth:        decision.HopDepth,
			Interface:       decision.Interface,
			Route:           decision.Route,
			Conflict:        decision.Conflict,
			ConflictWith:    decision.ConflictWith,
			Warning:         decision.Reason,
		})
	}
	if len(appliedRoutes) == 0 {
		return nil, errors.New("route plan did not select any routes to apply")
	}

	if start {
		ids := make([]int, 0, len(interfacesByAgent))
		for agentID := range interfacesByAgent {
			ids = append(ids, agentID)
		}
		sort.Ints(ids)

		AgentListMutex.Lock()
		agents := make(map[int]*controller.LigoloAgent, len(ids))
		for _, agentID := range ids {
			agents[agentID] = AgentList[agentID]
		}
		AgentListMutex.Unlock()

		for _, agentID := range ids {
			agent := agents[agentID]
			if agent == nil || !agent.Alive() || agent.Running {
				continue
			}
			if err := StartTunnel(agent, interfacesByAgent[agentID]); err != nil {
				return nil, fmt.Errorf("unable to start tunnel for agent %d: %w", agentID, err)
			}
		}
	}

	return appliedRoutes, nil
}

func relayConnectCommand(listenAddr, fingerprint, authToken string) string {
	host, port, err := net.SplitHostPort(listenAddr)
	if err != nil {
		return fmt.Sprintf("./agent -connect <relay-agent-reachable-ip>:%s -accept-fingerprint %s -relay-token %s", listenAddr, fingerprint, authToken)
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		return fmt.Sprintf("./agent -connect <relay-agent-reachable-ip>:%s -accept-fingerprint %s -relay-token %s", port, fingerprint, authToken)
	}
	return fmt.Sprintf("./agent -connect %s -accept-fingerprint %s -relay-token %s", net.JoinHostPort(host, port), fingerprint, authToken)
}

func relayListenPort(listenAddr string) string {
	_, port, err := net.SplitHostPort(listenAddr)
	if err != nil {
		return "<port>"
	}
	return port
}

func startRelayOnAgent(agent *controller.LigoloAgent, listenAddr, authToken string, tokenTTL time.Duration, oneTimeToken bool) (*controller.RelayStartResult, error) {
	result, err := agent.StartRelayWithOptions(controller.RelayStartOptions{
		ListenAddr:   listenAddr,
		AuthToken:    authToken,
		TokenTTL:     tokenTTL,
		OneTimeToken: oneTimeToken,
	})
	if err != nil {
		return nil, err
	}
	startRelayNotificationHandler(agent)
	return result, nil
}

func startRelayNotificationHandler(agent *controller.LigoloAgent) {
	go agent.HandleRelayNotifications(ChainMgr, func(a *controller.LigoloAgent) error {
		logrus.WithFields(logrus.Fields{
			"name":    a.Name,
			"session": a.SessionID,
			"via":     agent.Name,
		}).Info("Downstream agent connected via relay")
		return RegisterAgent(a)
	})
}

func relayTokenTTLFromSeconds(seconds int64) time.Duration {
	if seconds <= 0 {
		return controller.DefaultRelayTokenTTL
	}
	return time.Duration(seconds) * time.Second
}

func rotateRelayToken(agent *controller.LigoloAgent, authToken string, tokenTTL time.Duration, oneTimeToken bool) (*controller.RelayStartResult, error) {
	if !agent.RelayActive {
		return nil, errors.New("relay is not active")
	}
	listenAddr := agent.RelayListenAddr
	if err := stopRelayWithDownstream(agent); err != nil {
		return nil, err
	}
	return startRelayOnAgent(agent, listenAddr, authToken, tokenTTL, oneTimeToken)
}

type RelayDoctorReport struct {
	GeneratedAt time.Time           `json:"generated_at"`
	Status      string              `json:"status"`
	Warnings    []string            `json:"warnings,omitempty"`
	Chain       proxy.ChainSnapshot `json:"chain"`
	Routes      []ChainRouteInfo    `json:"routes,omitempty"`
	Relays      []RelayDoctorRelay  `json:"relays,omitempty"`
}

type RelayOpsReport struct {
	GeneratedAt  time.Time           `json:"generated_at"`
	Status       string              `json:"status"`
	Summary      RelayOpsSummary     `json:"summary"`
	Warnings     []string            `json:"warnings,omitempty"`
	Actions      []RelayOpsAction    `json:"actions,omitempty"`
	Chain        proxy.ChainSnapshot `json:"chain"`
	Routes       []ChainRouteInfo    `json:"routes,omitempty"`
	Relays       []RelayDoctorRelay  `json:"relays,omitempty"`
	RoutePlan    ChainRoutePlan      `json:"route_plan"`
	MeshHealth   []RelayMeshHealth   `json:"mesh_health,omitempty"`
	RepairPlan   ChainRepairPlan     `json:"repair_plan"`
	FailoverPlan ChainFailoverPlan   `json:"failover_plan"`
	AutoHeal     RelayAutoHealStatus `json:"auto_heal"`
}

type RelayOpsSummary struct {
	AgentsTotal             int `json:"agents_total"`
	AgentsOnline            int `json:"agents_online"`
	DirectAgents            int `json:"direct_agents"`
	RelayedAgents           int `json:"relayed_agents"`
	ActiveRelays            int `json:"active_relays"`
	DownstreamAgents        int `json:"downstream_agents"`
	ExpiredTokens           int `json:"expired_tokens"`
	RouteConflicts          int `json:"route_conflicts"`
	RoutePlanApply          int `json:"route_plan_apply"`
	RoutePlanSkipped        int `json:"route_plan_skipped"`
	MeshHealthy             int `json:"mesh_healthy"`
	MeshDegraded            int `json:"mesh_degraded"`
	MeshOffline             int `json:"mesh_offline"`
	MeshRepairable          int `json:"mesh_repairable"`
	RepairActions           int `json:"repair_actions"`
	RepairAutomated         int `json:"repair_automated"`
	RepairManual            int `json:"repair_manual"`
	FailoverRecommendations int `json:"failover_recommendations"`
	FailoverAtRisk          int `json:"failover_at_risk"`
	FailoverCommandReady    int `json:"failover_command_ready"`
	FailoverApplySupported  int `json:"failover_apply_supported"`
	Warnings                int `json:"warnings"`
	MaxDepth                int `json:"max_depth"`
}

type RelayOpsAction struct {
	Severity string `json:"severity"`
	AgentID  int    `json:"agent_id,omitempty"`
	Title    string `json:"title"`
	Detail   string `json:"detail,omitempty"`
}

type RelayDoctorRelay struct {
	AgentID   int                    `json:"agent_id"`
	Name      string                 `json:"name"`
	SessionID string                 `json:"session_id"`
	Alive     bool                   `json:"alive"`
	Relay     controller.RelayStatus `json:"relay"`
	Problems  []string               `json:"problems,omitempty"`
}

func relayDoctorReport(includeIPv6 bool, interfacePrefix string) RelayDoctorReport {
	snapshot := chainSnapshot()
	routes := chainRouteInfos(includeIPv6, interfacePrefix)
	report := RelayDoctorReport{
		GeneratedAt: time.Now(),
		Status:      "ok",
		Chain:       snapshot,
		Routes:      routes,
	}

	AgentListMutex.Lock()
	ids := make([]int, 0, len(AgentList))
	for agentID := range AgentList {
		ids = append(ids, agentID)
	}
	sort.Ints(ids)
	for _, agentID := range ids {
		agent := AgentList[agentID]
		status := agent.RelayStatusSnapshot()
		relay := RelayDoctorRelay{
			AgentID:   agentID,
			Name:      agent.Name,
			SessionID: agent.SessionID,
			Alive:     agent.Alive(),
			Relay:     status,
		}
		if !relay.Alive {
			relay.Problems = append(relay.Problems, "agent is offline")
		}
		if status.Active && status.TokenExpired {
			relay.Problems = append(relay.Problems, "relay auth token is expired")
		}
		if status.Active && status.CertFingerprint == "" {
			relay.Problems = append(relay.Problems, "relay fingerprint is missing")
		}
		if status.LastError != "" {
			relay.Problems = append(relay.Problems, status.LastError)
		}
		if len(relay.Problems) > 0 || status.Active || len(status.RecentEvents) > 0 {
			report.Relays = append(report.Relays, relay)
		}
	}
	AgentListMutex.Unlock()

	if len(snapshot.Agents) == 0 {
		report.Warnings = append(report.Warnings, "no agents are connected")
	}
	seenWarnings := make(map[string]bool)
	for _, route := range routes {
		if route.Conflict && !seenWarnings[route.Warning] {
			report.Warnings = append(report.Warnings, route.Warning)
			seenWarnings[route.Warning] = true
		}
	}
	for _, relay := range report.Relays {
		for _, problem := range relay.Problems {
			warning := fmt.Sprintf("agent %d: %s", relay.AgentID, problem)
			if !seenWarnings[warning] {
				report.Warnings = append(report.Warnings, warning)
				seenWarnings[warning] = true
			}
		}
	}
	if len(report.Warnings) > 0 {
		report.Status = "warning"
	}
	return report
}

func relayOpsReport(includeIPv6 bool, interfacePrefix string) RelayOpsReport {
	doctor := relayDoctorReport(includeIPv6, interfacePrefix)
	routePlan := chainRoutePlanFromSnapshot(doctor.Chain, doctor.Routes, false)
	meshHealth := relayMeshHealth(doctor)
	repairPlan := chainRepairPlanFromInputs(routePlan, meshHealth, false)
	failoverPlan := chainFailoverPlanFromSnapshot(doctor.Chain, failoverAgentStates(doctor.Chain), false)
	warnings := relayOpsWarnings(doctor.Warnings, routePlan, meshHealth, repairPlan, failoverPlan)
	report := RelayOpsReport{
		GeneratedAt:  doctor.GeneratedAt,
		Status:       "ok",
		Warnings:     warnings,
		Chain:        doctor.Chain,
		Routes:       doctor.Routes,
		Relays:       doctor.Relays,
		RoutePlan:    routePlan,
		MeshHealth:   meshHealth,
		RepairPlan:   repairPlan,
		FailoverPlan: failoverPlan,
		AutoHeal:     RelayAutoHealStatusSnapshot(),
	}
	report.Summary = relayOpsSummary(doctor, routePlan, meshHealth, repairPlan, failoverPlan)
	report.Summary.Warnings = len(warnings)
	report.Actions = relayOpsActions(doctor, routePlan, meshHealth, repairPlan, failoverPlan)
	if len(warnings) > 0 {
		report.Status = "warning"
	}
	return report
}

func relayOpsWarnings(base []string, routePlan ChainRoutePlan, meshHealth []RelayMeshHealth, repairPlan ChainRepairPlan, failoverPlan ChainFailoverPlan) []string {
	warnings := append([]string(nil), base...)
	for _, warning := range routePlan.Warnings {
		warnings = appendUniqueString(warnings, warning)
	}
	if repairPlan.Summary.Actions > 0 {
		warnings = appendUniqueString(warnings, fmt.Sprintf("repair plan has %d pending action(s)", repairPlan.Summary.Actions))
	}
	if failoverPlan.Summary.Recommendations > 0 {
		warnings = appendUniqueString(warnings, fmt.Sprintf("failover plan has %d recommendation(s)", failoverPlan.Summary.Recommendations))
	}
	if failoverPlan.Summary.AtRisk > 0 {
		warnings = appendUniqueString(warnings, fmt.Sprintf("failover plan has %d at-risk relayed agent(s)", failoverPlan.Summary.AtRisk))
	}
	for _, item := range meshHealth {
		for _, issue := range item.Issues {
			warnings = appendUniqueString(warnings, fmt.Sprintf("agent %d: %s", item.AgentID, issue))
		}
	}
	return warnings
}

func relayOpsSummary(report RelayDoctorReport, routePlan ChainRoutePlan, meshHealth []RelayMeshHealth, repairPlan ChainRepairPlan, failoverPlan ChainFailoverPlan) RelayOpsSummary {
	summary := RelayOpsSummary{
		MaxDepth: len(report.Chain.Agents),
		Warnings: len(report.Warnings),
	}
	if report.Chain.MaxDepth > 0 {
		summary.MaxDepth = report.Chain.MaxDepth
	}
	var walk func(nodes []proxy.ChainNode)
	walk = func(nodes []proxy.ChainNode) {
		for _, node := range nodes {
			summary.AgentsTotal++
			if node.Alive {
				summary.AgentsOnline++
			}
			if node.ParentSessionID == "" {
				summary.DirectAgents++
			} else {
				summary.RelayedAgents++
			}
			if node.RelayActive {
				summary.ActiveRelays++
			}
			summary.DownstreamAgents += node.DownstreamCount
			if node.RelayTokenExpired {
				summary.ExpiredTokens++
			}
			walk(node.Children)
		}
	}
	walk(report.Chain.Agents)
	for _, route := range report.Routes {
		if route.Conflict {
			summary.RouteConflicts++
		}
	}
	summary.RoutePlanApply = routePlan.Summary.Apply
	summary.RoutePlanSkipped = routePlan.Summary.Skipped
	meshSummary := relayMeshHealthSummary(meshHealth)
	summary.MeshHealthy = meshSummary.Healthy
	summary.MeshDegraded = meshSummary.Degraded
	summary.MeshOffline = meshSummary.Offline
	summary.MeshRepairable = meshSummary.Repairable
	summary.RepairActions = repairPlan.Summary.Actions
	summary.RepairAutomated = repairPlan.Summary.ApplySupported
	summary.RepairManual = repairPlan.Summary.Manual
	summary.FailoverRecommendations = failoverPlan.Summary.Recommendations
	summary.FailoverAtRisk = failoverPlan.Summary.AtRisk
	summary.FailoverCommandReady = failoverPlan.Summary.CommandReady
	summary.FailoverApplySupported = failoverPlan.Summary.ApplySupported
	return summary
}

func relayOpsActions(report RelayDoctorReport, routePlan ChainRoutePlan, meshHealth []RelayMeshHealth, repairPlan ChainRepairPlan, failoverPlan ChainFailoverPlan) []RelayOpsAction {
	var actions []RelayOpsAction
	if len(report.Chain.Agents) == 0 {
		actions = append(actions, RelayOpsAction{
			Severity: "warning",
			Title:    "Connect at least one agent",
			Detail:   "No agents are available for relay operations.",
		})
	}
	for _, relay := range report.Relays {
		if !relay.Alive {
			actions = append(actions, RelayOpsAction{
				Severity: "critical",
				AgentID:  relay.AgentID,
				Title:    "Restore agent connectivity",
				Detail:   fmt.Sprintf("%s is offline.", relay.Name),
			})
		}
		if relay.Relay.Active && relay.Relay.TokenExpired {
			actions = append(actions, RelayOpsAction{
				Severity: "critical",
				AgentID:  relay.AgentID,
				Title:    "Rotate expired relay token",
				Detail:   fmt.Sprintf("%s has an expired relay auth token.", relay.Name),
			})
		}
		for _, problem := range relay.Problems {
			actions = append(actions, RelayOpsAction{
				Severity: "warning",
				AgentID:  relay.AgentID,
				Title:    "Investigate relay problem",
				Detail:   problem,
			})
		}
	}
	seenRouteWarnings := make(map[string]bool)
	for _, route := range report.Routes {
		if !route.Conflict || seenRouteWarnings[route.Warning] {
			continue
		}
		actions = append(actions, RelayOpsAction{
			Severity: "warning",
			AgentID:  route.AgentID,
			Title:    "Resolve duplicate route candidate",
			Detail:   route.Warning,
		})
		seenRouteWarnings[route.Warning] = true
	}
	if routePlan.Summary.Skipped > 0 {
		actions = append(actions, RelayOpsAction{
			Severity: "warning",
			Title:    "Review smart route plan",
			Detail:   fmt.Sprintf("%d duplicate route candidate(s) will be skipped by chain autoroute.", routePlan.Summary.Skipped),
		})
	}
	if repairPlan.Summary.ApplySupported > 0 {
		actions = append(actions, RelayOpsAction{
			Severity: "warning",
			Title:    "Apply relay repair plan",
			Detail:   fmt.Sprintf("%d safe repair action(s) can be applied automatically.", repairPlan.Summary.ApplySupported),
		})
	}
	if failoverPlan.Summary.ApplySupported > 0 {
		actions = append(actions, RelayOpsAction{
			Severity: "warning",
			Title:    "Apply relay failover plan",
			Detail:   fmt.Sprintf("%d relayed agent(s) can reconnect through a better or safer parent.", failoverPlan.Summary.ApplySupported),
		})
	} else if failoverPlan.Summary.Recommendations > 0 {
		actions = append(actions, RelayOpsAction{
			Severity: "warning",
			Title:    "Review relay failover plan",
			Detail:   fmt.Sprintf("%d relayed agent(s) have a better or safer parent option.", failoverPlan.Summary.Recommendations),
		})
	}
	for _, item := range meshHealth {
		for _, recoveryAction := range item.RecoveryActions {
			actions = append(actions, RelayOpsAction{
				Severity: "warning",
				AgentID:  item.AgentID,
				Title:    "Repair degraded relay path",
				Detail:   recoveryAction,
			})
		}
	}
	return actions
}

func stopRelayWithDownstream(relayAgent *controller.LigoloAgent) error {
	descendants := ChainMgr.GetDescendantSessionIDs(relayAgent.SessionID)

	AgentListMutex.Lock()
	for _, sessionID := range descendants {
		for _, agent := range AgentList {
			if agent.SessionID != sessionID {
				continue
			}
			if agent.Running {
				select {
				case agent.CloseChan <- true:
				default:
				}
				agent.Running = false
			}
			if agent.Session != nil {
				agent.Session.Close()
			}
			agent.ParentAgentID = ""
		}
	}
	AgentListMutex.Unlock()

	for _, sessionID := range descendants {
		ChainMgr.RemoveAgent(sessionID)
	}
	return relayAgent.StopRelay()
}

func genRandomUUID() string {
	b := make([]byte, 8)
	_, err := rand.Read(b)
	if err != nil {
		logrus.Fatal(err)
	}
	return hex.EncodeToString(b)
}

func RegisterAgent(agent *controller.LigoloAgent) error {
	AgentListMutex.Lock()
	defer AgentListMutex.Unlock()
	var recovered bool

	for agentID, registeredAgents := range AgentList {
		if agent.SessionID == registeredAgents.SessionID {
			// Check if existing session is truly alive and functional
			sessionFunctional := false
			if registeredAgents.Session != nil {
				select {
				case <-registeredAgents.Session.CloseChan():
					// Session is closed
					logrus.Debugf("Existing session for %s is closed", agent.SessionID)
				default:
					// Session channel is not closed, verify it's actually working
					if registeredAgents.Alive() {
						// Try to open a test stream to verify functionality
						testStream, err := registeredAgents.Session.Open()
						if err != nil {
							logrus.Debugf("Session appears alive but cannot open stream: %v", err)
						} else {
							testStream.Close()
							sessionFunctional = true
						}
					}
				}
			}

			if sessionFunctional {
				// Session is truly alive and working, reject duplicate
				logrus.Infof("Agent %s already connected, rejecting duplicate from %s", agent.SessionID, agent.Session.RemoteAddr())
				// Close the duplicate connection gracefully
				if agent.Session != nil {
					agent.Session.Close()
				}
				return fmt.Errorf("agent %s already connected", agent.SessionID)
			}

			// Session is dead or non-functional, perform recovery
			logrus.Infof("Recovering agent: %s (ID: %d)", registeredAgents.Name, agentID)
			recovered = true

			// Close old session if it exists
			if registeredAgents.Session != nil {
				registeredAgents.Session.Close()
			}

			// Update to new session
			registeredAgents.Session = agent.Session

			// FIXED: Check if tunnel was running and clean up properly
			savedInterface := registeredAgents.Interface
			tunnelWasRunning := registeredAgents.Running

			// ALWAYS restore tunnel if an interface was previously configured
			if savedInterface != "" {
				logrus.Infof("Restoring tunnel for agent %s on interface %s", registeredAgents.Name, savedInterface)

				// Stop the old tunnel if somehow still running
				if tunnelWasRunning {
					select {
					case registeredAgents.CloseChan <- true:
					default:
					}
					// Wait for cleanup
					time.Sleep(500 * time.Millisecond)
				}

				// Reset running flag
				registeredAgents.Running = false

				// CRITICAL: Clean up any stale interface state
				if netinfo.InterfaceExist(savedInterface) {
					logrus.Infof("Cleaning up stale interface %s...", savedInterface)
					stun, err := netinfo.GetTunByName(savedInterface)
					if err == nil {
						// Get current routes from config
						configState, err := config.GetInterfaceConfigState()
						if err == nil {
							if ifaceConfig, ok := configState[savedInterface]; ok {
								// Delete existing routes
								for _, ifcfg := range ifaceConfig.Routes {
									if ifcfg.Active {
										logrus.Debugf("Removing stale route %s", ifcfg.Destination)
										if err := stun.DelRoute(ifcfg.Destination); err != nil {
											logrus.Debugf("Route removal: %v", err)
										}
									}
								}
							}
						}
						// Destroy interface to release old fd
						logrus.Debugf("Destroying stale interface %s...", savedInterface)
						if err := stun.Destroy(); err != nil {
							logrus.Warnf("Could not destroy interface: %v", err)
						}
						time.Sleep(200 * time.Millisecond)
					}
				}

				// Recreate interface with fresh fd
				logrus.Infof("Recreating interface %s...", savedInterface)
				if err := netinfo.CreateTUN(savedInterface); err != nil {
					logrus.Errorf("Could not recreate interface: %v", err)
					return fmt.Errorf("failed to recreate interface: %v", err)
				}

				// Start fresh tunnel on the SAME interface
				if err := StartTunnel(registeredAgents, savedInterface); err != nil {
					logrus.Errorf("Failed to restore tunnel: %v", err)
					return fmt.Errorf("failed to restore tunnel: %v", err)
				}
			}

			// FIXED: Properly restore listeners by recreating them
			var listenersToRestore []struct {
				listenerAddr string
				network      string
				redirectAddr string
			}

			// First, collect listener info and stop old listeners
			for _, listener := range registeredAgents.Listeners {
				if listener != nil {
					logrus.Infof("Collecting listener info for restoration: %s", listener.String())
					listenersToRestore = append(listenersToRestore, struct {
						listenerAddr string
						network      string
						redirectAddr string
					}{
						listenerAddr: listener.ListenerAddr(),
						network:      listener.Network(),
						redirectAddr: listener.RedirectAddr(),
					})
					// Stop the old listener (this will close the proxy-side resources)
					if err := listener.Stop(); err != nil {
						logrus.Warnf("Failed to stop old listener: %v", err)
					}
				}
			}

			// Clear the old listeners array
			registeredAgents.Listeners = []*proxy.LigoloListener{}

			// Give agent time to clean up old port bindings
			if len(listenersToRestore) > 0 {
				time.Sleep(500 * time.Millisecond)
			}

			// Now recreate listeners on the agent side with the new session
			for _, listenerInfo := range listenersToRestore {
				logrus.Infof("Restoring listener: [%s] %s => %s", listenerInfo.network, listenerInfo.listenerAddr, listenerInfo.redirectAddr)

				// AddListener will create a new listener on the agent side
				proxyListener, err := restoreAgentListenerWithRetry(registeredAgents, listenerInfo.listenerAddr, listenerInfo.network, listenerInfo.redirectAddr)
				if err != nil {
					logrus.Errorf("Failed to restore listener: %v", err)
					continue
				}

				// Start the relay for the new listener
				go func(l *proxy.LigoloListener, a *controller.LigoloAgent) {
					err := l.StartRelay()
					if err != nil {
						logrus.WithFields(logrus.Fields{"listener": l.String(), "agent": a.Name, "id": a.SessionID}).Warnf("Listener relay ended: %v", err)
					}
				}(proxyListener, registeredAgents)

				logrus.Infof("Listener restored successfully: %s", proxyListener.String())
			}

			// Restore relay if it was previously active
			if registeredAgents.RelayActive {
				savedRelayAddr := registeredAgents.RelayListenAddr
				savedRelayAuthToken := registeredAgents.RelayAuthToken
				savedRelayTokenExpiresAt := registeredAgents.RelayTokenExpiresAt
				savedRelayOneTimeToken := registeredAgents.RelayOneTimeToken
				savedRelayOneTimeTokenUsed := registeredAgents.RelayOneTimeTokenUsed
				// Reset relay state before restarting
				registeredAgents.RelayActive = false
				registeredAgents.RelayControl = nil

				if savedRelayOneTimeToken && savedRelayOneTimeTokenUsed {
					logrus.Warnf("Not restoring relay on agent %s because its one-time token was already used", registeredAgents.Name)
				} else {
					logrus.Infof("Restoring relay on agent %s at %s", registeredAgents.Name, savedRelayAddr)
					result, err := registeredAgents.StartRelayWithOptions(controller.RelayStartOptions{
						ListenAddr:     savedRelayAddr,
						AuthToken:      savedRelayAuthToken,
						TokenExpiresAt: savedRelayTokenExpiresAt,
						OneTimeToken:   savedRelayOneTimeToken,
					})
					if err != nil {
						logrus.Errorf("Failed to restore relay: %v", err)
					} else {
						logrus.Infof("Relay restored (fingerprint: %s, token expires: %s). Downstream agents can reconnect with: %s", result.CertFingerprint, result.TokenExpiresAt.Format(time.RFC3339), relayConnectCommand(savedRelayAddr, result.CertFingerprint, result.AuthToken))
						startRelayNotificationHandler(registeredAgents)
					}
				}
			}

			// Preserve parent agent ID for recovered downstream agents
			if agent.ParentAgentID != "" {
				registeredAgents.ParentAgentID = agent.ParentAgentID
			}

			return nil
		}
	}

	// New agent, not recovered
	if !recovered {
		if config.Config.GetBool(fmt.Sprintf("agent.%s.autobind", agent.SessionID)) {
			autobindInterface := config.Config.GetString(fmt.Sprintf("agent.%s.interface", agent.SessionID))
			logrus.Infof("Starting autobind session: %s on interface %s", agent.SessionID, autobindInterface)
			if err := StartTunnel(agent, autobindInterface); err != nil {
				logrus.Error("unable to start tunnel for autobind: ", err)
			}
		}
	}

	AgentCounter++
	AgentList[AgentCounter] = agent
	return nil
}

func restoreAgentListenerWithRetry(agent *controller.LigoloAgent, listenerAddr, network, redirectAddr string) (*proxy.LigoloListener, error) {
	var lastErr error
	for attempt := 1; attempt <= 6; attempt++ {
		proxyListener, err := agent.AddListener(listenerAddr, network, redirectAddr)
		if err == nil {
			return proxyListener, nil
		}
		lastErr = err
		if !isTransientListenerRestoreError(err) {
			break
		}
		logrus.Warnf("Listener restore attempt %d for %s failed: %v", attempt, listenerAddr, err)
		time.Sleep(time.Duration(attempt) * 250 * time.Millisecond)
	}
	return nil, lastErr
}

func isTransientListenerRestoreError(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "address already in use") || strings.Contains(message, "bind")
}

func StartTunnel(agent *controller.LigoloAgent, tunName string) error {
	configState, err := config.GetInterfaceConfigState()
	if err != nil {
		return err
	}

	interfaceExists := netinfo.InterfaceExist(tunName)

	// Create interface if needed
	if _, ok := configState[tunName]; ok {
		if runtime.GOOS == "linux" && !interfaceExists {
			logrus.Debugf("Creating tun interface %s", tunName)
			if err := netinfo.CreateTUN(tunName); err != nil {
				return fmt.Errorf("failed to create TUN interface: %w", err)
			}
		}
	} else if !interfaceExists {
		logrus.Debugf("Creating tun interface %s (no prior config)", tunName)
		if err := netinfo.CreateTUN(tunName); err != nil {
			return fmt.Errorf("failed to create TUN interface: %w", err)
		}
	}

	logrus.Infof("Starting tunnel to %s (%s)", agent.Name, agent.SessionID)
	ligoloStack, err := proxy.NewLigoloTunnel(netstack.StackSettings{
		TunName:     tunName,
		MaxInflight: 4096,
	})
	if err != nil {
		return err
	}

	// Add routes
	if ifaceConfig, ok := configState[tunName]; ok {
		for _, ifcfg := range ifaceConfig.Routes {
			logrus.Debugf("Adding route %s on interface %s", ifcfg.Destination, tunName)
			tun, err := netinfo.GetTunByName(tunName)
			if err != nil {
				logrus.Warnf("Could not get TUN interface: %v", err)
				continue
			}
			if err := tun.AddRoute(ifcfg.Destination); err != nil {
				if strings.Contains(err.Error(), "file exists") || strings.Contains(err.Error(), "exists") {
					logrus.Debugf("Route %s already exists", ifcfg.Destination)
				} else {
					logrus.Warnf("Could not add route %s: %v", ifcfg.Destination, err)
				}
			}
		}
	}

	ifName, err := ligoloStack.GetStack().Interface().Name()
	if err != nil {
		logrus.Warn("unable to get interface name, err:", err)
		ifName = tunName
	}
	agent.Interface = ifName
	agent.Running = true

	ctx, cancelTunnel := context.WithCancel(context.Background())

	go ligoloStack.HandleSession(agent.Session, ctx)

	// Watchdog
	go func() {
		for {
			select {
			case <-agent.CloseChan:
				logrus.Infof("Closing tunnel to %s (%s)...", agent.Name, agent.SessionID)
				cancelTunnel()
				agent.Running = false

				// Clean up routes on user stop
				if netinfo.InterfaceExist(agent.Interface) {
					tun, err := netinfo.GetTunByName(agent.Interface)
					if err == nil {
						configState, err := config.GetInterfaceConfigState()
						if err == nil {
							if ifaceConfig, ok := configState[agent.Interface]; ok {
								for _, ifcfg := range ifaceConfig.Routes {
									logrus.Debugf("Removing route %s", ifcfg.Destination)
									tun.DelRoute(ifcfg.Destination)
								}
							}
						}
					}
				}
				return

			case <-agent.Session.CloseChan():
				logrus.Warnf("Lost tunnel connection with agent %s (%s)!", agent.Name, agent.SessionID)

				// FIXED: Properly clean up the old tunnel when agent drops
				agent.Running = false
				cancelTunnel()

				// CRITICAL FIX: Remove routes from the stale interface
				// These routes point to the old (now closed) TUN fd
				if netinfo.InterfaceExist(agent.Interface) {
					logrus.Infof("Cleaning up stale routes on %s after connection loss", agent.Interface)
					tun, err := netinfo.GetTunByName(agent.Interface)
					if err == nil {
						configState, err := config.GetInterfaceConfigState()
						if err == nil {
							if ifaceConfig, ok := configState[agent.Interface]; ok {
								for _, ifcfg := range ifaceConfig.Routes {
									logrus.Debugf("Removing stale route %s", ifcfg.Destination)
									if err := tun.DelRoute(ifcfg.Destination); err != nil {
										logrus.Debugf("Route removal: %v", err)
									}
								}
							}
						}
					}
					// Destroy the interface to release the stale fd
					logrus.Debugf("Destroying stale interface %s", agent.Interface)
					if err := tun.Destroy(); err != nil {
						logrus.Warnf("Could not destroy interface: %v", err)
					}
				}

				if currentAgent, ok := AgentList[CurrentAgentID]; ok {
					if currentAgent.SessionID == agent.SessionID {
						App.SetDefaultPrompt()
					}
				}

				logrus.Infof("Tunnel cleaned up, waiting for agent %s to reconnect...", agent.Name)
				return
			}
		}
	}()

	return nil
}

func Run() {
	// AgentList contains all the connected agents
	AgentList = make(map[int]*controller.LigoloAgent)

	App.AddCommand(&grumble.Command{
		Name:  "session",
		Help:  "Change the current relay agent",
		Usage: "session",
		Run: func(c *grumble.Context) error {
			AgentListMutex.Lock()
			sessionCount := 0
			for _, agent := range AgentList {
				if agent.Alive() {
					sessionCount += 1
				}
			}
			if sessionCount == 0 {
				AgentListMutex.Unlock()
				return errors.New("no sessions available")
			}
			AgentListMutex.Unlock()
			var session string
			sessionSelector := &survey.Select{
				Message: "Specify a session :",
				Options: func() (out []string) {
					AgentListMutex.Lock()
					for id, agent := range AgentList {
						if agent.Alive() {
							out = append(out, fmt.Sprintf("%d - %s", id, agent.String()))
						}
					}
					AgentListMutex.Unlock()
					return
				}(),
			}
			err := survey.AskOne(sessionSelector, &session)
			if err != nil {
				return err
			}

			s := strings.Split(session, " ")
			sessionID, err := strconv.Atoi(s[0])
			if err != nil {
				return err
			}

			CurrentAgentID = sessionID
			c.App.SetPrompt(fmt.Sprintf("[Agent : %s] » ", AgentList[CurrentAgentID].Name))
			return nil
		},
	})

	App.AddCommand(&grumble.Command{
		Name:  "certificate_fingerprint",
		Help:  "Show the current selfcert fingerprint",
		Usage: "certificate_fingerprint",
		Run: func(c *grumble.Context) error {
			selfcrt, err := ProxyController.GetSelfCertificateSignature()
			if err != nil {
				return err
			}
			if selfcrt == nil {
				return errors.New("certificate is nil")
			}
			logrus.Printf("TLS Certificate fingerprint for %s is: %X\n", ProxyController.CertManagerConfig.SelfcertDomain, sha256.Sum256(selfcrt.Certificate[0]))
			return nil
		},
	})

	App.AddCommand(&grumble.Command{
		Name:  "connect_agent",
		Help:  "Attempt to connect to a bind agent",
		Usage: "connect_agent --ip [agentip]",
		Flags: func(f *grumble.Flags) {
			f.StringL("ip", "", "The agent ip:port")
			f.BoolL("ignore-cert", false, "Ignore TLS certificate verification")
		},
		Run: func(c *grumble.Context) error {
			tlsConfig := &tls.Config{}
			tlsConfig.InsecureSkipVerify = true

			remoteConn, err := tls.Dial("tcp", c.Flags.String("ip"), tlsConfig)
			if err != nil {
				return err
			}
			if !c.Flags.Bool("ignore-cert") {
				cert := remoteConn.ConnectionState().PeerCertificates[0].Raw
				shaSum := sha256.Sum256(cert)
				confirmTLS := false
				prompt := &survey.Confirm{
					Message: fmt.Sprintf("TLS Certificate Fingerprint is: %X, connect?", shaSum),
				}
				survey.AskOne(prompt, &confirmTLS)
				if !confirmTLS {
					remoteConn.Close()
					return errors.New("connection aborted (user did not validate TLS cert)")
				}
			}

			yamuxConn, err := yamux.Client(remoteConn, nil)
			if err != nil {
				return err
			}

			agent, err := controller.NewAgent(yamuxConn)
			if err != nil {
				logrus.Errorf("could not register agent, error: %v", err)
				return err
			}

			logrus.WithFields(logrus.Fields{"remote": remoteConn.RemoteAddr(), "name": agent.Name, "id": agent.SessionID}).Info("Agent connected.")

			if err := RegisterAgent(agent); err != nil {
				logrus.Errorf("could not register agent: %s", err.Error())
			}
			return nil
		},
	})

	App.AddCommand(&grumble.Command{
		Name:      "tunnel_start",
		Help:      "Start relaying connection to the current agent",
		Usage:     "tunnel_start --tun ligolo",
		HelpGroup: "Tunneling",
		Aliases:   []string{"start"},
		Flags: func(f *grumble.Flags) {
			f.StringL("tun", "ligolo", "the interface to run the proxy on")
		},
		Run: func(c *grumble.Context) error {
			if _, ok := AgentList[CurrentAgentID]; !ok {
				return ErrInvalidAgent
			}
			CurrentAgent := AgentList[CurrentAgentID]

			if CurrentAgent.Session == nil {
				return ErrInvalidAgent
			}

			if CurrentAgent.Running {
				return ErrAlreadyRunning
			}

			for _, agent := range AgentList {
				if agent.Running {
					if agent.Interface == c.Flags.String("tun") && agent.Alive() {
						return errors.New("a tunnel is already using this interface name. Please use a different name using the --tun option")
					}
				}
			}

			if err := StartTunnel(CurrentAgent, c.Flags.String("tun")); err != nil {
				return fmt.Errorf("unable to start tunnel: %s", err.Error())
			}
			return nil
		},
	})

	App.AddCommand(&grumble.Command{
		Name:      "tunnel_list",
		Help:      "List active tunnels and sessions",
		Usage:     "tunnel_list",
		HelpGroup: "Tunneling",
		Aliases:   []string{"session_list"},
		Run: func(c *grumble.Context) error {
			t := table.NewWriter()
			t.SetStyle(table.StyleLight)
			t.SetTitle("Active sessions and tunnels")
			t.AppendHeader(table.Row{"#", "Agent", "Interface", "Via", "Status"})

			AgentListMutex.Lock()
			for id, agent := range AgentList {
				var status string
				if agent.Alive() {
					status = text.Colors{text.FgGreen}.Sprintf("Online")
				} else {
					status = text.Colors{text.FgRed}.Sprintf("Offline (Awaiting recovery)")
				}
				via := "(direct)"
				if agent.ParentAgentID != "" {
					// Find parent agent name
					for _, a := range AgentList {
						if a.SessionID == agent.ParentAgentID {
							via = fmt.Sprintf("via %s", a.Name)
							break
						}
					}
				}
				t.AppendRow(table.Row{id, agent.String(), agent.Interface, via, status})
			}
			AgentListMutex.Unlock()
			App.Println(t.Render())
			return nil
		},
	})

	App.AddCommand(&grumble.Command{
		Name:      "tunnel_stop",
		Help:      "Stop the tunnel",
		Usage:     "stop",
		HelpGroup: "Tunneling",
		Aliases:   []string{"stop"},
		Flags: func(f *grumble.Flags) {
			f.IntL("agent", -1, "The agent to stop")
		},
		Run: func(c *grumble.Context) error {
			var selectedAgent int
			if c.Flags.Int("agent") != -1 {
				selectedAgent = c.Flags.Int("agent")
			} else {
				selectedAgent = CurrentAgentID
			}
			if _, ok := AgentList[selectedAgent]; !ok {
				return ErrInvalidAgent
			}

			CurrentAgent := AgentList[selectedAgent]

			if CurrentAgent.Session == nil || !CurrentAgent.Running {
				return ErrNotRunning
			}
			CurrentAgent.CloseChan <- true
			CurrentAgent.Running = false
			return nil
		},
	})

	App.AddCommand(&grumble.Command{
		Name:  "ifconfig",
		Help:  "Show agent interfaces",
		Usage: "ifconfig",
		Run: func(c *grumble.Context) error {
			if _, ok := AgentList[CurrentAgentID]; !ok {
				return ErrInvalidAgent
			}
			CurrentAgent := AgentList[CurrentAgentID]
			// Note: Network information is not refreshed when calling this command
			if CurrentAgent.Session == nil {
				return ErrInvalidAgent
			}
			for n, ifaceInfo := range CurrentAgent.Network {
				t := table.NewWriter()
				t.SetStyle(table.StyleLight)
				t.SetTitle(fmt.Sprintf("Interface %d", n))

				t.AppendRow(table.Row{"Name", ifaceInfo.Name})
				t.AppendRow(table.Row{"Hardware MAC", ifaceInfo.HardwareAddr})
				t.AppendRow(table.Row{"MTU", ifaceInfo.MTU})
				t.AppendRow(table.Row{"Flags", ifaceInfo.Flags})

				for _, address := range ifaceInfo.Addresses {
					if address != "" {
						ip, _, err := net.ParseCIDR(address)
						if err != nil {
							continue
						}
						if ip.To4() != nil {
							t.AppendRow(table.Row{"IPv4 Address", address})
						} else {
							t.AppendRow(table.Row{"IPv6 Address", address})
						}
					}
				}
				App.Println(t.Render())
			}
			return nil
		},
	})

	App.AddCommand(&grumble.Command{
		Name:      "listener_list",
		Help:      "List currently running listeners",
		Usage:     "listener_list",
		HelpGroup: "Listeners",
		Run: func(c *grumble.Context) error {
			t := table.NewWriter()
			t.SetStyle(table.StyleLight)
			t.SetTitle("Active listeners")
			t.AppendHeader(table.Row{"#", "Agent", "Network", "Agent listener address", "Proxy redirect address", "Status"})

			for _, agent := range AgentList {
				for _, listener := range agent.Listeners {
					var status string
					if agent.Alive() {
						status = text.Colors{text.FgGreen}.Sprintf("Online")
					} else {
						status = text.Colors{text.FgRed}.Sprintf("Offline")
					}
					t.AppendRow(table.Row{listener.ID, agent.String(), listener.Network(), listener.ListenerAddr(), listener.RedirectAddr(), status})
				}
			}

			c.App.Println(t.Render())
			return nil
		},
	})

	App.AddCommand(&grumble.Command{
		Name:      "listener_stop",
		Help:      "Stop a listener",
		Usage:     "listener_stop",
		HelpGroup: "Listeners",
		Run: func(c *grumble.Context) error {
			var session string
			type LigoloListenerAgent struct {
				listener *proxy.LigoloListener
				agent    *controller.LigoloAgent
			}
			listenerMap := make(map[int]LigoloListenerAgent)
			listenerSelector := &survey.Select{
				Message: "Specify the listener to stop:",
				Options: func() (out []string) {
					AgentListMutex.Lock()
					i := 0
					for _, agent := range AgentList {
						for _, listener := range agent.Listeners {
							if listener != nil {
								var status string
								if agent.Alive() {
									status = text.Colors{text.FgGreen}.Sprintf("Online")
								} else {
									status = text.Colors{text.FgRed}.Sprintf("Offline")
								}
								out = append(out, fmt.Sprintf("%d - Agent: %s - Net: %s - Agent Listener: %s - Redirect: %s [%s]", i, agent.String(), listener.Network(), listener.ListenerAddr(), listener.RedirectAddr(), status))
								listenerMap[i] = LigoloListenerAgent{listener: listener, agent: agent}
								i++
							}
						}
					}
					AgentListMutex.Unlock()
					return
				}(),
			}

			err := survey.AskOne(listenerSelector, &session)
			if err != nil {
				return err
			}

			s := strings.Split(session, " ")
			selectionIndex, err := strconv.Atoi(s[0])
			if err != nil {
				return err
			}

			if listenerInfo, ok := listenerMap[selectionIndex]; ok {
				// Stop the listener
				if err := listenerInfo.listener.Stop(); err != nil {
					return err
				}
				// Delete from agent's slice using listener.ID (which is the slice index)
				listenerInfo.agent.DeleteListener(int(listenerInfo.listener.ID))
				logrus.Infof("Listener stopped: %s", listenerInfo.listener.String())
			} else {
				return errors.New("invalid listener id")
			}
			return nil
		},
	})

	App.AddCommand(&grumble.Command{
		Name:      "listener_add",
		Help:      "Listen on the agent and redirect connections to the desired address",
		Usage:     "listener_add --addr [agent_listening_address:port] --to [local_listening_address:port] --tcp/--udp",
		HelpGroup: "Listeners",
		Flags: func(f *grumble.Flags) {
			f.BoolL("tcp", false, "Use TCP listener")
			f.BoolL("udp", false, "Use UDP listener")
			f.StringL("addr", "", "The agent listening address:port")
			f.StringL("to", "", "Where to redirect connections")
		},
		Run: func(c *grumble.Context) error {
			if _, ok := AgentList[CurrentAgentID]; !ok {
				return ErrInvalidAgent
			}
			CurrentAgent := AgentList[CurrentAgentID]
			if CurrentAgent.Session == nil {
				return errors.New("please, select an agent using the session command")
			}
			var netProto string

			if c.Flags.Bool("tcp") && c.Flags.Bool("udp") {
				return errors.New("choose TCP or UDP, not both")
			}
			if c.Flags.Bool("tcp") {
				netProto = "tcp"
			}
			if c.Flags.Bool("udp") {
				netProto = "udp"
			}
			if netProto == "" {
				netProto = "tcp" // Use TCP by default.
			}

			if c.Flags.String("to") == "" {
				return errors.New("please, specify a valid redirect (to) IP address - expected format : ip:port")
			}

			// Check if specified IP is valid.
			if _, _, err := net.SplitHostPort(c.Flags.String("to")); err != nil {
				return err
			}
			if _, _, err := net.SplitHostPort(c.Flags.String("addr")); err != nil {
				return err
			}

			proxyListener, err := CurrentAgent.AddListener(c.Flags.String("addr"), netProto, c.Flags.String("to"))
			if err != nil {
				return err
			}

			logrus.Infof("Listener %d created on remote agent!", proxyListener.ID)

			go func() {
				err := proxyListener.StartRelay()
				if err != nil {
					// FIXED: Log relay errors as warnings to prevent cascade failures
					// This is critical for double-pivot scenarios (e.g., DC01 -> DMZ01 -> Proxy)
					logrus.WithFields(logrus.Fields{"listener": proxyListener.String(), "agent": CurrentAgent.Name, "id": CurrentAgent.SessionID}).Warnf("Listener relay ended: %v", err)
					return
				}

				logrus.WithFields(logrus.Fields{"listener": proxyListener.String(), "agent": CurrentAgent.Name, "id": CurrentAgent.SessionID}).Info("Listener ended without error")
				return
			}()

			return nil
		},
	})

	App.AddCommand(&grumble.Command{
		Name:    "kill",
		Help:    "Kill the current agent",
		Usage:   "kill",
		Aliases: []string{"agent_kill", "session_kill"},
		Run: func(c *grumble.Context) error {
			if _, ok := AgentList[CurrentAgentID]; !ok {
				return ErrInvalidAgent
			}
			currentAgent := AgentList[CurrentAgentID]
			if ask("Are you sure to kill the current agent?") {
				return currentAgent.Kill()
			}
			return nil
		},
	})

	App.AddCommand(&grumble.Command{
		Name:      "relay_start",
		Help:      "Start relay mode on the current agent to accept downstream agents",
		Usage:     "relay_start --addr <agent-interface-ip>:11602",
		HelpGroup: "Relay",
		Flags: func(f *grumble.Flags) {
			f.StringL("addr", "127.0.0.1:11602", "The address:port the agent should listen on for downstream agents")
			f.StringL("relay-token", "", "Optional downstream relay auth token; generated when empty")
			f.StringL("token-ttl", controller.DefaultRelayTokenTTL.String(), "Relay auth token lifetime (for example 15m, 8h)")
			f.BoolL("one-time-token", false, "Allow the relay token to authenticate one downstream agent only")
		},
		Run: func(c *grumble.Context) error {
			if _, ok := AgentList[CurrentAgentID]; !ok {
				return ErrInvalidAgent
			}
			currentAgent := AgentList[CurrentAgentID]
			if currentAgent.Session == nil {
				return ErrInvalidAgent
			}
			if !currentAgent.RelayCapable {
				return errors.New("this agent does not support relay mode")
			}
			if currentAgent.RelayActive {
				return fmt.Errorf("relay already active on %s", currentAgent.RelayListenAddr)
			}
			tokenTTL, err := time.ParseDuration(c.Flags.String("token-ttl"))
			if err != nil || tokenTTL <= 0 {
				return fmt.Errorf("invalid token TTL %q", c.Flags.String("token-ttl"))
			}

			result, err := startRelayOnAgent(currentAgent, c.Flags.String("addr"), c.Flags.String("relay-token"), tokenTTL, c.Flags.Bool("one-time-token"))
			if err != nil {
				return fmt.Errorf("could not start relay: %v", err)
			}

			logrus.Infof("Relay started on agent %s at %s", currentAgent.Name, c.Flags.String("addr"))
			logrus.Infof("TLS Certificate fingerprint: %s", result.CertFingerprint)
			logrus.Infof("Relay auth token: %s", result.AuthToken)
			logrus.Infof("Relay token expires: %s", result.TokenExpiresAt.Format(time.RFC3339))
			logrus.Infof("Downstream agents can connect with: %s", relayConnectCommand(c.Flags.String("addr"), result.CertFingerprint, result.AuthToken))
			logrus.Infof("Debug fallback only: ./agent -connect <relay-agent-reachable-ip>:%s -ignore-cert -relay-token %s", relayListenPort(c.Flags.String("addr")), result.AuthToken)

			return nil
		},
	})

	App.AddCommand(&grumble.Command{
		Name:      "relay_token_rotate",
		Help:      "Rotate the current agent relay token by restarting its relay listener",
		Usage:     "relay_token_rotate [--relay-token token] [--token-ttl 8h] [--one-time-token]",
		HelpGroup: "Relay",
		Flags: func(f *grumble.Flags) {
			f.StringL("relay-token", "", "Optional new downstream relay auth token; generated when empty")
			f.StringL("token-ttl", controller.DefaultRelayTokenTTL.String(), "Relay auth token lifetime (for example 15m, 8h)")
			f.BoolL("one-time-token", false, "Allow the new relay token to authenticate one downstream agent only")
		},
		Run: func(c *grumble.Context) error {
			if _, ok := AgentList[CurrentAgentID]; !ok {
				return ErrInvalidAgent
			}
			currentAgent := AgentList[CurrentAgentID]
			tokenTTL, err := time.ParseDuration(c.Flags.String("token-ttl"))
			if err != nil || tokenTTL <= 0 {
				return fmt.Errorf("invalid token TTL %q", c.Flags.String("token-ttl"))
			}
			result, err := rotateRelayToken(currentAgent, c.Flags.String("relay-token"), tokenTTL, c.Flags.Bool("one-time-token"))
			if err != nil {
				return err
			}
			logrus.Infof("Relay token rotated for agent %s", currentAgent.Name)
			logrus.Infof("TLS Certificate fingerprint: %s", result.CertFingerprint)
			logrus.Infof("Relay auth token: %s", result.AuthToken)
			logrus.Infof("Relay token expires: %s", result.TokenExpiresAt.Format(time.RFC3339))
			logrus.Infof("Downstream agents can connect with: %s", relayConnectCommand(currentAgent.RelayListenAddr, result.CertFingerprint, result.AuthToken))
			return nil
		},
	})

	App.AddCommand(&grumble.Command{
		Name:      "relay_token_revoke",
		Help:      "Revoke the current relay token by stopping relay mode",
		Usage:     "relay_token_revoke",
		HelpGroup: "Relay",
		Run: func(c *grumble.Context) error {
			if _, ok := AgentList[CurrentAgentID]; !ok {
				return ErrInvalidAgent
			}
			currentAgent := AgentList[CurrentAgentID]
			if !currentAgent.RelayActive {
				return errors.New("relay is not active on this agent")
			}
			return stopRelayWithDownstream(currentAgent)
		},
	})

	App.AddCommand(&grumble.Command{
		Name:      "relay_stop",
		Help:      "Stop relay mode on the current agent",
		Usage:     "relay_stop",
		HelpGroup: "Relay",
		Run: func(c *grumble.Context) error {
			if _, ok := AgentList[CurrentAgentID]; !ok {
				return ErrInvalidAgent
			}
			currentAgent := AgentList[CurrentAgentID]
			if !currentAgent.RelayActive {
				return errors.New("relay is not active on this agent")
			}

			downstream := ChainMgr.GetDownstreamSessionIDs(currentAgent.SessionID)
			if len(downstream) > 0 {
				if !ask(fmt.Sprintf("Stopping relay will disconnect %d downstream agent(s). Continue?", len(downstream))) {
					return nil
				}
			}

			return stopRelayWithDownstream(currentAgent)
		},
	})

	App.AddCommand(&grumble.Command{
		Name:      "chain_list",
		Help:      "Show the relay chain topology",
		Usage:     "chain_list [--json]",
		HelpGroup: "Relay",
		Flags: func(f *grumble.Flags) {
			f.BoolL("json", false, "print structured JSON")
		},
		Run: func(c *grumble.Context) error {
			snapshot := chainSnapshot()
			if c.Flags.Bool("json") {
				encoded, err := json.MarshalIndent(snapshot, "", "  ")
				if err != nil {
					return err
				}
				App.Println(string(encoded))
				return nil
			}

			App.Println(snapshot.Topology)
			return nil
		},
	})

	App.AddCommand(&grumble.Command{
		Name:      "relay_doctor",
		Help:      "Show relay health, token status, recent events, and route warnings",
		Usage:     "relay_doctor [--json] [--with-ipv6] [--interface-prefix ligolo]",
		HelpGroup: "Relay",
		Flags: func(f *grumble.Flags) {
			f.BoolL("json", false, "print structured JSON")
			f.BoolL("with-ipv6", false, "include IPv6 route candidates")
			f.StringL("interface-prefix", "ligolo", "interface prefix used for route conflict checks")
		},
		Run: func(c *grumble.Context) error {
			report := relayDoctorReport(c.Flags.Bool("with-ipv6"), c.Flags.String("interface-prefix"))
			if c.Flags.Bool("json") {
				encoded, err := json.MarshalIndent(report, "", "  ")
				if err != nil {
					return err
				}
				App.Println(string(encoded))
				return nil
			}
			App.Println(report.Chain.Topology)
			if len(report.Warnings) == 0 {
				App.Println("Relay doctor: ok")
				return nil
			}
			for _, warning := range report.Warnings {
				App.Printf("Relay doctor warning: %s\n", warning)
			}
			return nil
		},
	})
}
