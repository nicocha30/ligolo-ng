// Ligolo-ng Relay
// Copyright (C) 2025 Nicolas Chatelain (nicocha30)

package app

import (
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/allsmog/ligolo-ng-relay/cmd/proxy/config"
	"github.com/allsmog/ligolo-ng-relay/pkg/controller"
	"github.com/allsmog/ligolo-ng-relay/pkg/proxy"
	"github.com/allsmog/ligolo-ng-relay/pkg/proxy/netinfo"
)

const (
	routeDecisionApply        = "apply"
	routeDecisionSkipConflict = "skip_conflict"

	repairActionEnsureRoute          = "ensure_route"
	repairActionStartTunnel          = "start_tunnel"
	repairActionPruneDuplicateRoute  = "prune_duplicate_route"
	repairActionRotateToken          = "rotate_token"
	repairActionWaitReconnect        = "wait_reconnect"
	repairActionInspectPath          = "inspect_path"
	repairActionRestartRelay         = "restart_relay"
	repairActionInspectRelayEvents   = "inspect_relay_events"
	repairActionOperatorIntervention = "operator_intervention"
)

type ChainRoutePlan struct {
	GeneratedAt time.Time             `json:"generated_at"`
	Status      string                `json:"status"`
	Summary     ChainRoutePlanSummary `json:"summary"`
	Warnings    []string              `json:"warnings,omitempty"`
	Decisions   []ChainRouteDecision  `json:"decisions"`
}

type ChainRoutePlanSummary struct {
	Candidates        int `json:"candidates"`
	Apply             int `json:"apply"`
	Skipped           int `json:"skipped"`
	ConflictGroups    int `json:"conflict_groups"`
	AlreadyConfigured int `json:"already_configured"`
	StartTunnels      int `json:"start_tunnels"`
}

type ChainRouteDecision struct {
	AgentID           int    `json:"agent_id"`
	Name              string `json:"name"`
	SessionID         string `json:"session_id"`
	ParentSessionID   string `json:"parent_session_id"`
	HopDepth          int    `json:"hop_depth"`
	Interface         string `json:"interface"`
	Route             string `json:"route"`
	RouteKey          string `json:"route_key"`
	Decision          string `json:"decision"`
	Reason            string `json:"reason"`
	Conflict          bool   `json:"conflict"`
	ConflictWith      []int  `json:"conflict_with,omitempty"`
	Preferred         bool   `json:"preferred"`
	Score             int    `json:"score"`
	Alive             bool   `json:"alive"`
	AgentState        string `json:"agent_state"`
	PathRTTMS         *int64 `json:"path_rtt_ms,omitempty"`
	TunnelRunning     bool   `json:"tunnel_running"`
	RelayActive       bool   `json:"relay_active"`
	AlreadyConfigured bool   `json:"already_configured"`
	StartTunnel       bool   `json:"start_tunnel"`
}

type RelayMeshHealthSummary struct {
	Total      int `json:"total"`
	Healthy    int `json:"healthy"`
	Degraded   int `json:"degraded"`
	Offline    int `json:"offline"`
	Repairable int `json:"repairable"`
}

type RelayMeshHealth struct {
	AgentID         int      `json:"agent_id"`
	Name            string   `json:"name"`
	SessionID       string   `json:"session_id"`
	ParentSessionID string   `json:"parent_session_id"`
	HopDepth        int      `json:"hop_depth"`
	State           string   `json:"state"`
	Alive           bool     `json:"alive"`
	PathRTTMS       *int64   `json:"path_rtt_ms,omitempty"`
	TunnelRunning   bool     `json:"tunnel_running"`
	RelayActive     bool     `json:"relay_active"`
	DownstreamCount int      `json:"downstream_count"`
	Issues          []string `json:"issues,omitempty"`
	RecoveryActions []string `json:"recovery_actions,omitempty"`
}

type ChainRepairPlan struct {
	GeneratedAt time.Time              `json:"generated_at"`
	Status      string                 `json:"status"`
	Summary     ChainRepairPlanSummary `json:"summary"`
	Actions     []ChainRepairAction    `json:"actions"`
}

type ChainRepairPlanSummary struct {
	Actions        int `json:"actions"`
	ApplySupported int `json:"apply_supported"`
	Applied        int `json:"applied"`
	Failed         int `json:"failed"`
	RouteEnsures   int `json:"route_ensures"`
	TunnelStarts   int `json:"tunnel_starts"`
	Prunes         int `json:"prunes"`
	Manual         int `json:"manual"`
}

type ChainRepairAction struct {
	Type           string `json:"type"`
	Severity       string `json:"severity"`
	AgentID        int    `json:"agent_id,omitempty"`
	Name           string `json:"name,omitempty"`
	SessionID      string `json:"session_id,omitempty"`
	Interface      string `json:"interface,omitempty"`
	Route          string `json:"route,omitempty"`
	RouteKey       string `json:"route_key,omitempty"`
	Reason         string `json:"reason"`
	ApplySupported bool   `json:"apply_supported"`
	Applied        bool   `json:"applied"`
	Error          string `json:"error,omitempty"`
}

type ChainFailoverPlan struct {
	GeneratedAt     time.Time                     `json:"generated_at"`
	Status          string                        `json:"status"`
	Summary         ChainFailoverPlanSummary      `json:"summary"`
	Recommendations []ChainFailoverRecommendation `json:"recommendations,omitempty"`
}

type ChainFailoverPlanSummary struct {
	RelayedAgents   int `json:"relayed_agents"`
	AtRisk          int `json:"at_risk"`
	Recommendations int `json:"recommendations"`
	CommandReady    int `json:"command_ready"`
	ApplySupported  int `json:"apply_supported"`
	Applied         int `json:"applied"`
	Failed          int `json:"failed"`
	NoAlternative   int `json:"no_alternative"`
}

type ChainFailoverRecommendation struct {
	AgentID                int                   `json:"agent_id"`
	Name                   string                `json:"name"`
	SessionID              string                `json:"session_id"`
	HopDepth               int                   `json:"hop_depth"`
	CurrentParentAgentID   int                   `json:"current_parent_agent_id,omitempty"`
	CurrentParentName      string                `json:"current_parent_name,omitempty"`
	CurrentParentSessionID string                `json:"current_parent_session_id"`
	CurrentParentIssues    []string              `json:"current_parent_issues,omitempty"`
	Reason                 string                `json:"reason"`
	RecommendedParent      *ChainFailoverParent  `json:"recommended_parent,omitempty"`
	Alternatives           []ChainFailoverParent `json:"alternatives,omitempty"`
	CommandAvailable       bool                  `json:"command_available"`
	ApplySupported         bool                  `json:"apply_supported"`
	Applied                bool                  `json:"applied"`
	Error                  string                `json:"error,omitempty"`
	ConnectCommand         string                `json:"connect_command,omitempty"`
}

type ChainFailoverParent struct {
	AgentID          int        `json:"agent_id"`
	Name             string     `json:"name"`
	SessionID        string     `json:"session_id"`
	HopDepth         int        `json:"hop_depth"`
	ListenAddr       string     `json:"listen_addr"`
	ReconnectAddr    string     `json:"reconnect_addr,omitempty"`
	Fingerprint      string     `json:"fingerprint,omitempty"`
	TokenExpiresAt   *time.Time `json:"token_expires_at,omitempty"`
	TokenExpired     bool       `json:"token_expired"`
	OneTimeToken     bool       `json:"one_time_token"`
	OneTimeTokenUsed bool       `json:"one_time_token_used"`
	PathRTTMS        *int64     `json:"path_rtt_ms,omitempty"`
	DownstreamCount  int        `json:"downstream_count"`
	Score            int        `json:"score"`
	CommandAvailable bool       `json:"command_available"`
	BlockedReason    string     `json:"blocked_reason,omitempty"`
	authToken        string     `json:"-"`
}

type failoverAgentState struct {
	node      proxy.ChainNode
	relay     controller.RelayStatus
	authToken string
}

func chainRoutePlan(includeIPv6 bool, interfacePrefix string, start bool) ChainRoutePlan {
	snapshot := chainSnapshot()
	routes := chainRouteInfos(includeIPv6, interfacePrefix)
	return chainRoutePlanFromSnapshot(snapshot, routes, start)
}

func chainFailoverPlan(includeCommands bool) ChainFailoverPlan {
	snapshot := chainSnapshot()
	return chainFailoverPlanFromSnapshot(snapshot, failoverAgentStates(snapshot), includeCommands)
}

func applyChainFailoverPlan(includeCommands bool, all bool, sessionIDs []string, agentIDs []int) ChainFailoverPlan {
	return applyChainFailoverPlanWithLimit(includeCommands, all, sessionIDs, agentIDs, 0)
}

func applyChainFailoverPlanWithLimit(includeCommands bool, all bool, sessionIDs []string, agentIDs []int, maxRecommendations int) ChainFailoverPlan {
	plan := chainFailoverPlan(includeCommands)
	selectedSessions := selectedFailoverSessions(all, sessionIDs, agentIDs, plan.Recommendations)

	AgentListMutex.Lock()
	agentsBySessionID := make(map[string]*controller.LigoloAgent, len(AgentList))
	for _, agent := range AgentList {
		agentsBySessionID[agent.SessionID] = agent
	}
	AgentListMutex.Unlock()

	attempted := 0
	for index := range plan.Recommendations {
		recommendation := &plan.Recommendations[index]
		if !selectedSessions[recommendation.SessionID] {
			continue
		}
		if !recommendation.ApplySupported {
			recommendation.Error = "recommendation is not auto-apply supported"
			continue
		}
		if recommendation.RecommendedParent == nil {
			recommendation.Error = "recommendation has no parent target"
			continue
		}
		agent := agentsBySessionID[recommendation.SessionID]
		if agent == nil {
			recommendation.Error = "agent is not registered"
			continue
		}
		if maxRecommendations > 0 && attempted >= maxRecommendations {
			continue
		}
		attempted++
		if err := applyChainFailoverRecommendation(agent, *recommendation.RecommendedParent); err != nil {
			recommendation.Error = err.Error()
			continue
		}
		recommendation.Applied = true
	}
	summarizeFailoverPlan(&plan)
	return plan
}

func chainFailoverPlanFromSnapshot(snapshot proxy.ChainSnapshot, states map[string]failoverAgentState, includeCommands bool) ChainFailoverPlan {
	plan := ChainFailoverPlan{
		GeneratedAt: time.Now(),
		Status:      "ok",
	}
	walkChainNodes(snapshot.Agents, func(node proxy.ChainNode) {
		if node.ParentSessionID == "" {
			return
		}
		plan.Summary.RelayedAgents++
		currentParent, hasCurrentParent := states[node.ParentSessionID]
		var currentIssues []string
		if hasCurrentParent {
			currentIssues = failoverParentIssues(currentParent)
		} else {
			currentIssues = []string{"current parent is not registered"}
		}
		if len(currentIssues) > 0 {
			plan.Summary.AtRisk++
		}

		candidates := failoverCandidatesFor(node, states)
		if len(candidates) == 0 {
			plan.Summary.NoAlternative++
			if len(currentIssues) > 0 {
				plan.Recommendations = append(plan.Recommendations, ChainFailoverRecommendation{
					AgentID:                node.AgentID,
					Name:                   node.Name,
					SessionID:              node.SessionID,
					HopDepth:               node.HopDepth,
					CurrentParentAgentID:   currentParent.node.AgentID,
					CurrentParentName:      currentParent.node.Name,
					CurrentParentSessionID: node.ParentSessionID,
					CurrentParentIssues:    currentIssues,
					Reason:                 "current relay parent is at risk and no valid alternate relay parent is available",
				})
			}
			return
		}

		recommended := candidates[0]
		currentScore := failoverParentScore(currentParent.node)
		if len(currentIssues) == 0 && recommended.Score <= currentScore {
			return
		}

		reason := "alternate relay parent has lower failover cost"
		if len(currentIssues) > 0 {
			reason = "current relay parent is at risk"
		}
		recommendation := ChainFailoverRecommendation{
			AgentID:                node.AgentID,
			Name:                   node.Name,
			SessionID:              node.SessionID,
			HopDepth:               node.HopDepth,
			CurrentParentAgentID:   currentParent.node.AgentID,
			CurrentParentName:      currentParent.node.Name,
			CurrentParentSessionID: node.ParentSessionID,
			CurrentParentIssues:    currentIssues,
			Reason:                 reason,
			RecommendedParent:      &recommended,
			Alternatives:           candidates,
			CommandAvailable:       recommended.CommandAvailable,
			ApplySupported:         recommended.CommandAvailable && recommended.ReconnectAddr != "",
		}
		if includeCommands && recommended.CommandAvailable {
			connectAddr := recommended.ReconnectAddr
			if connectAddr == "" {
				connectAddr = recommended.ListenAddr
			}
			recommendation.ConnectCommand = relayConnectCommand(connectAddr, recommended.Fingerprint, recommended.authToken)
		}
		if recommendation.CommandAvailable {
			plan.Summary.CommandReady++
		}
		if recommendation.ApplySupported {
			plan.Summary.ApplySupported++
		}
		plan.Recommendations = append(plan.Recommendations, recommendation)
	})
	plan.Summary.Recommendations = len(plan.Recommendations)
	if plan.Summary.AtRisk > 0 || plan.Summary.Recommendations > 0 {
		plan.Status = "warning"
	}
	return plan
}

func selectedFailoverSessions(all bool, sessionIDs []string, agentIDs []int, recommendations []ChainFailoverRecommendation) map[string]bool {
	selected := make(map[string]bool)
	agentIDsBySession := make(map[int]string, len(recommendations))
	for _, recommendation := range recommendations {
		agentIDsBySession[recommendation.AgentID] = recommendation.SessionID
		if all {
			selected[recommendation.SessionID] = true
		}
	}
	for _, sessionID := range sessionIDs {
		sessionID = strings.TrimSpace(sessionID)
		if sessionID != "" {
			selected[sessionID] = true
		}
	}
	for _, agentID := range agentIDs {
		if sessionID := agentIDsBySession[agentID]; sessionID != "" {
			selected[sessionID] = true
		}
	}
	return selected
}

func splitCSVStrings(value string) []string {
	var values []string
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		if item != "" {
			values = append(values, item)
		}
	}
	return values
}

func splitCSVInts(value string) ([]int, error) {
	var values []int
	for _, item := range splitCSVStrings(value) {
		parsed, err := strconv.Atoi(item)
		if err != nil {
			return nil, fmt.Errorf("invalid integer %q", item)
		}
		values = append(values, parsed)
	}
	return values, nil
}

func applyChainFailoverRecommendation(agent *controller.LigoloAgent, parent ChainFailoverParent) error {
	if parent.ReconnectAddr == "" {
		return fmt.Errorf("recommended parent does not expose a concrete reconnect address")
	}
	if parent.Fingerprint == "" || parent.authToken == "" {
		return fmt.Errorf("recommended parent is missing reconnect credentials")
	}
	if err := agent.UpdateReconnectTarget(parent.ReconnectAddr, parent.Fingerprint, parent.authToken); err != nil {
		return err
	}
	AgentListMutex.Lock()
	if agent.Running {
		select {
		case agent.CloseChan <- true:
		default:
		}
		agent.Running = false
	}
	session := agent.Session
	AgentListMutex.Unlock()
	if session != nil {
		session.Close()
	}
	ChainMgr.RemoveAgent(agent.SessionID)
	return nil
}

func summarizeFailoverPlan(plan *ChainFailoverPlan) {
	plan.Summary.Applied = 0
	plan.Summary.Failed = 0
	plan.Status = "ok"
	for _, recommendation := range plan.Recommendations {
		if recommendation.Applied {
			plan.Summary.Applied++
		}
		if recommendation.Error != "" {
			plan.Summary.Failed++
		}
	}
	if plan.Summary.Failed > 0 {
		plan.Status = "error"
	} else if plan.Summary.AtRisk > 0 || plan.Summary.Recommendations > 0 {
		plan.Status = "warning"
	}
}

func failoverAgentStates(snapshot proxy.ChainSnapshot) map[string]failoverAgentState {
	nodesBySession := flattenChainNodes(snapshot.Agents)
	states := make(map[string]failoverAgentState, len(nodesBySession))

	AgentListMutex.Lock()
	defer AgentListMutex.Unlock()
	for _, agent := range AgentList {
		node, ok := nodesBySession[agent.SessionID]
		if !ok {
			continue
		}
		states[agent.SessionID] = failoverAgentState{
			node:      node,
			relay:     agent.RelayStatusSnapshot(),
			authToken: agent.RelayAuthToken,
		}
	}
	return states
}

func failoverCandidatesFor(target proxy.ChainNode, states map[string]failoverAgentState) []ChainFailoverParent {
	descendants := descendantSessionIDsFromNode(target)
	candidates := make([]ChainFailoverParent, 0, len(states))
	for _, state := range states {
		node := state.node
		if node.SessionID == target.SessionID || node.SessionID == target.ParentSessionID {
			continue
		}
		if descendants[node.SessionID] {
			continue
		}
		parent := failoverParentFromState(state)
		if parent.BlockedReason != "" {
			continue
		}
		if wouldExceedFailoverDepth(target, parent) {
			continue
		}
		candidates = append(candidates, parent)
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].Score != candidates[j].Score {
			return candidates[i].Score > candidates[j].Score
		}
		return candidates[i].AgentID < candidates[j].AgentID
	})
	return candidates
}

func failoverParentFromState(state failoverAgentState) ChainFailoverParent {
	node := state.node
	relay := state.relay
	parent := ChainFailoverParent{
		AgentID:          node.AgentID,
		Name:             node.Name,
		SessionID:        node.SessionID,
		HopDepth:         node.HopDepth,
		ListenAddr:       node.RelayListenAddr,
		ReconnectAddr:    relayReconnectAddr(node),
		Fingerprint:      node.RelayCertFingerprint,
		TokenExpiresAt:   node.RelayTokenExpiresAt,
		TokenExpired:     node.RelayTokenExpired,
		OneTimeToken:     node.RelayOneTimeToken,
		OneTimeTokenUsed: relay.OneTimeTokenUsed,
		PathRTTMS:        cloneInt64(node.PathRTTMS),
		DownstreamCount:  node.DownstreamCount,
		authToken:        state.authToken,
		CommandAvailable: state.authToken != "" && node.RelayCertFingerprint != "" && node.RelayListenAddr != "" && !node.RelayTokenExpired && !relay.OneTimeTokenUsed,
	}
	parent.Score = failoverParentScore(node)
	if !node.Alive {
		parent.BlockedReason = "relay parent is offline"
	} else if !node.RelayActive {
		parent.BlockedReason = "relay is not active"
	} else if node.RelayListenAddr == "" {
		parent.BlockedReason = "relay listen address is missing"
	} else if node.RelayCertFingerprint == "" {
		parent.BlockedReason = "relay fingerprint is missing"
	} else if node.RelayTokenExpired {
		parent.BlockedReason = "relay token is expired"
	} else if relay.OneTimeTokenUsed {
		parent.BlockedReason = "relay one-time token is already used"
	} else if state.authToken == "" {
		parent.BlockedReason = "relay token is not available in proxy memory"
	}
	return parent
}

func relayReconnectAddr(node proxy.ChainNode) string {
	host, port, err := net.SplitHostPort(node.RelayListenAddr)
	if err != nil {
		return node.RelayListenAddr
	}
	if host != "" && host != "0.0.0.0" && host != "::" {
		return net.JoinHostPort(host, port)
	}
	remoteHost, _, err := net.SplitHostPort(node.RemoteAddr)
	if err != nil || remoteHost == "" {
		return ""
	}
	return net.JoinHostPort(remoteHost, port)
}

func failoverParentIssues(state failoverAgentState) []string {
	node := state.node
	var issues []string
	if state.node.SessionID == "" {
		return []string{"current parent is not registered"}
	}
	if !node.Alive {
		issues = append(issues, "current parent is offline")
	}
	if !node.RelayActive {
		issues = append(issues, "current parent relay is not active")
	}
	if node.RelayTokenExpired {
		issues = append(issues, "current parent relay token is expired")
	}
	if state.relay.OneTimeTokenUsed {
		issues = append(issues, "current parent relay one-time token is already used")
	}
	if node.RelayActive && node.RelayCertFingerprint == "" {
		issues = append(issues, "current parent relay fingerprint is missing")
	}
	if node.RelayActive && state.authToken == "" {
		issues = append(issues, "current parent relay token is not available in proxy memory")
	}
	return issues
}

func failoverParentScore(node proxy.ChainNode) int {
	score := 0
	if node.Alive {
		score += 10000
	}
	if node.RelayActive {
		score += 1000
	}
	if !node.RelayTokenExpired {
		score += 500
	}
	score -= node.HopDepth * 1000
	if node.PathRTTMS == nil {
		score -= 250
	} else {
		score -= int(*node.PathRTTMS)
	}
	score -= node.DownstreamCount * 50
	return score
}

func descendantSessionIDsFromNode(node proxy.ChainNode) map[string]bool {
	descendants := make(map[string]bool)
	walkChainNodes(node.Children, func(child proxy.ChainNode) {
		descendants[child.SessionID] = true
	})
	return descendants
}

func wouldExceedFailoverDepth(target proxy.ChainNode, parent ChainFailoverParent) bool {
	return parent.HopDepth+1+maxRelativeDescendantDepth(target) >= proxy.MaxChainDepth
}

func maxRelativeDescendantDepth(node proxy.ChainNode) int {
	maxDepth := 0
	var walk func(children []proxy.ChainNode, depth int)
	walk = func(children []proxy.ChainNode, depth int) {
		for _, child := range children {
			if depth > maxDepth {
				maxDepth = depth
			}
			walk(child.Children, depth+1)
		}
	}
	walk(node.Children, 1)
	return maxDepth
}

func chainRepairPlan(includeIPv6 bool, interfacePrefix string, start bool, pruneConflicts bool) ChainRepairPlan {
	doctor := relayDoctorReport(includeIPv6, interfacePrefix)
	routePlan := chainRoutePlanFromSnapshot(doctor.Chain, doctor.Routes, start)
	meshHealth := relayMeshHealth(doctor)
	return chainRepairPlanFromInputs(routePlan, meshHealth, pruneConflicts)
}

func applyChainRepairPlan(includeIPv6 bool, interfacePrefix string, start bool, pruneConflicts bool) ChainRepairPlan {
	return applyChainRepairPlanWithLimit(includeIPv6, interfacePrefix, start, pruneConflicts, 0)
}

func applyChainRepairPlanWithLimit(includeIPv6 bool, interfacePrefix string, start bool, pruneConflicts bool, maxActions int) ChainRepairPlan {
	plan := chainRepairPlan(includeIPv6, interfacePrefix, start, pruneConflicts)
	if len(plan.Actions) == 0 {
		return plan
	}

	AgentListMutex.Lock()
	agents := make(map[int]*controller.LigoloAgent, len(AgentList))
	for agentID, agent := range AgentList {
		agents[agentID] = agent
	}
	AgentListMutex.Unlock()

	startedAgents := make(map[int]bool)
	attempted := 0
	for index := range plan.Actions {
		action := &plan.Actions[index]
		if !action.ApplySupported {
			continue
		}
		if maxActions > 0 && attempted >= maxActions {
			continue
		}
		attempted++
		var err error
		switch action.Type {
		case repairActionEnsureRoute:
			err = ensureRepairRoute(action.Interface, action.Route)
		case repairActionStartTunnel:
			if startedAgents[action.AgentID] {
				action.Applied = true
				continue
			}
			err = startRepairTunnel(agents[action.AgentID], action.Interface)
			if err == nil {
				startedAgents[action.AgentID] = true
			}
		case repairActionPruneDuplicateRoute:
			err = pruneRepairRoute(action.Interface, action.Route)
		default:
			err = fmt.Errorf("unsupported repair action %q", action.Type)
		}
		if err != nil {
			action.Error = err.Error()
			continue
		}
		action.Applied = true
	}
	summarizeRepairPlan(&plan)
	return plan
}

func chainRepairPlanFromInputs(routePlan ChainRoutePlan, meshHealth []RelayMeshHealth, pruneConflicts bool) ChainRepairPlan {
	plan := ChainRepairPlan{
		GeneratedAt: time.Now(),
		Status:      "ok",
	}
	seenActions := make(map[string]bool)

	for _, decision := range routePlan.Decisions {
		if decision.Decision == routeDecisionApply {
			if !decision.AlreadyConfigured {
				appendRepairAction(&plan, seenActions, ChainRepairAction{
					Type:           repairActionEnsureRoute,
					Severity:       "warning",
					AgentID:        decision.AgentID,
					Name:           decision.Name,
					SessionID:      decision.SessionID,
					Interface:      decision.Interface,
					Route:          decision.Route,
					RouteKey:       decision.RouteKey,
					Reason:         "preferred route is not configured",
					ApplySupported: true,
				})
			}
			if decision.StartTunnel {
				appendRepairAction(&plan, seenActions, ChainRepairAction{
					Type:           repairActionStartTunnel,
					Severity:       "warning",
					AgentID:        decision.AgentID,
					Name:           decision.Name,
					SessionID:      decision.SessionID,
					Interface:      decision.Interface,
					Reason:         "preferred route owner has no running tunnel",
					ApplySupported: true,
				})
			}
			continue
		}
		if pruneConflicts && decision.AlreadyConfigured {
			appendRepairAction(&plan, seenActions, ChainRepairAction{
				Type:           repairActionPruneDuplicateRoute,
				Severity:       "warning",
				AgentID:        decision.AgentID,
				Name:           decision.Name,
				SessionID:      decision.SessionID,
				Interface:      decision.Interface,
				Route:          decision.Route,
				RouteKey:       decision.RouteKey,
				Reason:         fmt.Sprintf("duplicate route is configured but agent %d is preferred", preferredAgentIDForRoute(routePlan.Decisions, decision.RouteKey)),
				ApplySupported: true,
			})
		}
	}

	for _, item := range meshHealth {
		for _, issue := range item.Issues {
			actionType, reason := repairActionForMeshIssue(item, issue)
			appendRepairAction(&plan, seenActions, ChainRepairAction{
				Type:           actionType,
				Severity:       severityForMeshState(item.State),
				AgentID:        item.AgentID,
				Name:           item.Name,
				SessionID:      item.SessionID,
				Reason:         reason,
				ApplySupported: false,
			})
		}
	}

	summarizeRepairPlan(&plan)
	return plan
}

func appendRepairAction(plan *ChainRepairPlan, seen map[string]bool, action ChainRepairAction) {
	key := strings.Join([]string{
		action.Type,
		strconv.Itoa(action.AgentID),
		action.Interface,
		action.Route,
		action.Reason,
	}, "\x00")
	if seen[key] {
		return
	}
	seen[key] = true
	plan.Actions = append(plan.Actions, action)
}

func summarizeRepairPlan(plan *ChainRepairPlan) {
	plan.Summary = ChainRepairPlanSummary{
		Actions: len(plan.Actions),
	}
	plan.Status = "ok"
	for _, action := range plan.Actions {
		if action.ApplySupported {
			plan.Summary.ApplySupported++
		} else {
			plan.Summary.Manual++
		}
		if action.Applied {
			plan.Summary.Applied++
		}
		if action.Error != "" {
			plan.Summary.Failed++
		}
		switch action.Type {
		case repairActionEnsureRoute:
			plan.Summary.RouteEnsures++
		case repairActionStartTunnel:
			plan.Summary.TunnelStarts++
		case repairActionPruneDuplicateRoute:
			plan.Summary.Prunes++
		}
	}
	if plan.Summary.Failed > 0 {
		plan.Status = "error"
	} else if plan.Summary.Actions > 0 {
		plan.Status = "warning"
	}
}

func repairActionForMeshIssue(item RelayMeshHealth, issue string) (string, string) {
	switch {
	case strings.Contains(issue, "offline"):
		return repairActionWaitReconnect, "wait for matching SessionID reconnect; the proxy restores tunnel, listener, and relay state"
	case strings.Contains(issue, "health probe"):
		return repairActionInspectPath, "inspect transport latency or rerun relay ops after the probe cache expires"
	case strings.Contains(issue, "expired"):
		return repairActionRotateToken, fmt.Sprintf("rotate relay token for agent %d and redistribute the new downstream command", item.AgentID)
	case strings.Contains(issue, "fingerprint"):
		return repairActionRestartRelay, fmt.Sprintf("restart relay on agent %d so downstream agents can pin a valid fingerprint", item.AgentID)
	case strings.Contains(issue, "relay"):
		return repairActionInspectRelayEvents, fmt.Sprintf("inspect relay event history for agent %d", item.AgentID)
	default:
		return repairActionOperatorIntervention, issue
	}
}

func severityForMeshState(state string) string {
	if state == "offline" {
		return "critical"
	}
	if state == "degraded" {
		return "warning"
	}
	return "info"
}

func preferredAgentIDForRoute(decisions []ChainRouteDecision, routeKey string) int {
	for _, decision := range decisions {
		if decision.RouteKey == routeKey && decision.Preferred {
			return decision.AgentID
		}
	}
	return 0
}

func ensureRepairRoute(iface, route string) error {
	if iface == "" || route == "" {
		return errors.New("repair route action is missing interface or route")
	}
	if err := config.EnsureInterfaceConfig(iface); err != nil {
		return err
	}
	return config.EnsureRouteConfig(iface, route)
}

func startRepairTunnel(agent *controller.LigoloAgent, iface string) error {
	if agent == nil {
		return errors.New("agent is no longer registered")
	}
	if !agent.Alive() {
		return errors.New("agent is offline")
	}
	if agent.Running {
		return nil
	}
	if iface == "" {
		return errors.New("repair tunnel action is missing interface")
	}
	return StartTunnel(agent, iface)
}

func pruneRepairRoute(iface, route string) error {
	if iface == "" || route == "" {
		return errors.New("repair prune action is missing interface or route")
	}
	var failures []string
	if cfg := config.GetInterfaceConfig(iface); cfg != nil {
		if err := config.DeleteRouteConfig(iface, route); err != nil {
			failures = append(failures, err.Error())
		}
	}
	if netinfo.InterfaceExist(iface) {
		tun, err := netinfo.GetTunByName(iface)
		if err != nil {
			failures = append(failures, err.Error())
		} else if err := tun.DelRoute(route); err != nil && !isMissingRouteError(err) {
			failures = append(failures, err.Error())
		}
	}
	if len(failures) > 0 {
		return errors.New(strings.Join(failures, "; "))
	}
	return nil
}

func isMissingRouteError(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "not found") ||
		strings.Contains(message, "no such process") ||
		strings.Contains(message, "does not exist")
}

func chainRoutePlanFromSnapshot(snapshot proxy.ChainSnapshot, routes []ChainRouteInfo, start bool) ChainRoutePlan {
	plan := ChainRoutePlan{
		GeneratedAt: time.Now(),
		Status:      "ok",
	}
	if len(routes) == 0 {
		plan.Warnings = append(plan.Warnings, "no route candidates available")
		plan.Status = "warning"
		return plan
	}

	nodesBySession := flattenChainNodes(snapshot.Agents)
	configured := configuredRouteKeys()
	decisions := make([]ChainRouteDecision, 0, len(routes))
	groups := make(map[string][]int)

	for _, route := range routes {
		node, ok := nodesBySession[route.SessionID]
		alive := ok && node.Alive
		agentState := "unknown"
		if ok {
			agentState = node.State
		}
		decision := ChainRouteDecision{
			AgentID:           route.AgentID,
			Name:              route.Name,
			SessionID:         route.SessionID,
			ParentSessionID:   route.ParentSessionID,
			HopDepth:          route.HopDepth,
			Interface:         route.Interface,
			Route:             route.Route,
			RouteKey:          routeConflictKey(route.Route),
			Decision:          routeDecisionApply,
			Conflict:          route.Conflict,
			ConflictWith:      append([]int(nil), route.ConflictWith...),
			Alive:             alive,
			AgentState:        agentState,
			AlreadyConfigured: routeAlreadyConfigured(configured, route.Interface, route.Route),
		}
		if ok {
			decision.PathRTTMS = cloneInt64(node.PathRTTMS)
			decision.TunnelRunning = node.TunnelRunning
			decision.RelayActive = node.RelayActive
		}
		decision.Score = routeDecisionScore(decision)
		decisions = append(decisions, decision)
		groups[decision.RouteKey] = append(groups[decision.RouteKey], len(decisions)-1)
	}

	for routeKey, indexes := range groups {
		sort.Slice(indexes, func(i, j int) bool {
			return betterRouteDecision(decisions[indexes[i]], decisions[indexes[j]])
		})
		preferredIndex := indexes[0]
		preferred := decisions[preferredIndex]
		if len(indexes) > 1 {
			plan.Summary.ConflictGroups++
			plan.Warnings = append(plan.Warnings, fmt.Sprintf("route %s has %d candidates; selected agent %d", routeKey, len(indexes), preferred.AgentID))
		}
		for _, index := range indexes {
			decision := &decisions[index]
			decision.Conflict = len(indexes) > 1
			decision.ConflictWith = conflictPeerAgentIDs(decisions, indexes, decision.AgentID)
			if index == preferredIndex {
				decision.Decision = routeDecisionApply
				decision.Preferred = true
				decision.StartTunnel = start && decision.Alive && !decision.TunnelRunning
				decision.Reason = routeApplyReason(*decision, len(indexes) > 1)
				continue
			}
			decision.Decision = routeDecisionSkipConflict
			decision.Reason = fmt.Sprintf("skipped duplicate CIDR; agent %d has the preferred route cost", preferred.AgentID)
			decision.StartTunnel = false
		}
	}

	sort.Slice(decisions, func(i, j int) bool {
		if decisions[i].RouteKey != decisions[j].RouteKey {
			return decisions[i].RouteKey < decisions[j].RouteKey
		}
		if decisions[i].Preferred != decisions[j].Preferred {
			return decisions[i].Preferred
		}
		return decisions[i].AgentID < decisions[j].AgentID
	})

	plan.Decisions = decisions
	plan.Summary.Candidates = len(decisions)
	for _, decision := range decisions {
		if decision.Decision == routeDecisionApply {
			plan.Summary.Apply++
		} else {
			plan.Summary.Skipped++
		}
		if decision.AlreadyConfigured {
			plan.Summary.AlreadyConfigured++
		}
		if decision.StartTunnel {
			plan.Summary.StartTunnels++
		}
	}
	if plan.Summary.Skipped > 0 || len(plan.Warnings) > 0 {
		plan.Status = "warning"
	}
	return plan
}

func routeApplyReason(decision ChainRouteDecision, hadConflict bool) string {
	parts := []string{}
	if hadConflict {
		parts = append(parts, "selected preferred duplicate candidate")
	} else {
		parts = append(parts, "selected unique route candidate")
	}
	if decision.HopDepth == 0 {
		parts = append(parts, "direct agent")
	} else {
		parts = append(parts, fmt.Sprintf("%d-hop path", decision.HopDepth))
	}
	if decision.PathRTTMS != nil {
		parts = append(parts, fmt.Sprintf("%d ms RTT", *decision.PathRTTMS))
	}
	if decision.AlreadyConfigured {
		parts = append(parts, "route already configured")
	}
	if decision.StartTunnel {
		parts = append(parts, "tunnel will be started")
	}
	return strings.Join(parts, "; ")
}

func routeDecisionScore(decision ChainRouteDecision) int {
	score := 0
	if decision.Alive {
		score += 10000
	}
	score -= decision.HopDepth * 1000
	if decision.PathRTTMS == nil {
		score -= 500
	} else {
		score -= int(*decision.PathRTTMS)
	}
	if decision.TunnelRunning {
		score += 100
	}
	if decision.RelayActive {
		score += 10
	}
	return score
}

func betterRouteDecision(left, right ChainRouteDecision) bool {
	if left.Alive != right.Alive {
		return left.Alive
	}
	if left.HopDepth != right.HopDepth {
		return left.HopDepth < right.HopDepth
	}
	if (left.PathRTTMS == nil) != (right.PathRTTMS == nil) {
		return right.PathRTTMS == nil
	}
	if left.PathRTTMS != nil && right.PathRTTMS != nil && *left.PathRTTMS != *right.PathRTTMS {
		return *left.PathRTTMS < *right.PathRTTMS
	}
	if left.TunnelRunning != right.TunnelRunning {
		return left.TunnelRunning
	}
	return left.AgentID < right.AgentID
}

func conflictPeerAgentIDs(decisions []ChainRouteDecision, indexes []int, agentID int) []int {
	peers := make([]int, 0, len(indexes)-1)
	for _, index := range indexes {
		peer := decisions[index].AgentID
		if peer != agentID {
			peers = append(peers, peer)
		}
	}
	sort.Ints(peers)
	return peers
}

func configuredRouteKeys() map[string]map[string]bool {
	state, err := config.GetInterfaceConfigState()
	if err != nil {
		return nil
	}
	configured := make(map[string]map[string]bool, len(state))
	for iface, info := range state {
		if configured[iface] == nil {
			configured[iface] = make(map[string]bool)
		}
		for _, route := range info.Routes {
			configured[iface][route.Destination] = true
			configured[iface][routeConflictKey(route.Destination)] = true
		}
	}
	return configured
}

func routeAlreadyConfigured(configured map[string]map[string]bool, iface, route string) bool {
	if configured == nil {
		return false
	}
	routes, ok := configured[iface]
	if !ok {
		return false
	}
	return routes[route] || routes[routeConflictKey(route)]
}

func relayMeshHealth(report RelayDoctorReport) []RelayMeshHealth {
	relaysBySession := make(map[string]RelayDoctorRelay, len(report.Relays))
	for _, relay := range report.Relays {
		relaysBySession[relay.SessionID] = relay
	}

	var health []RelayMeshHealth
	walkChainNodes(report.Chain.Agents, func(node proxy.ChainNode) {
		item := RelayMeshHealth{
			AgentID:         node.AgentID,
			Name:            node.Name,
			SessionID:       node.SessionID,
			ParentSessionID: node.ParentSessionID,
			HopDepth:        node.HopDepth,
			State:           "healthy",
			Alive:           node.Alive,
			PathRTTMS:       cloneInt64(node.PathRTTMS),
			TunnelRunning:   node.TunnelRunning,
			RelayActive:     node.RelayActive,
			DownstreamCount: node.DownstreamCount,
		}
		if !node.Alive {
			item.Issues = appendUniqueString(item.Issues, "agent is offline")
			item.RecoveryActions = appendUniqueString(item.RecoveryActions, "wait for reconnect; matching SessionID recovery will restore tunnel, listeners, and relay state")
		}
		if node.Alive && node.PathRTTMS == nil {
			item.Issues = appendUniqueString(item.Issues, "path health probe did not complete")
			item.RecoveryActions = appendUniqueString(item.RecoveryActions, "run relayctl ops again or inspect agent transport latency")
		}
		if node.RelayActive && node.RelayTokenExpired {
			item.Issues = appendUniqueString(item.Issues, "relay auth token is expired")
			item.RecoveryActions = appendUniqueString(item.RecoveryActions, fmt.Sprintf("rotate relay token for agent %d", node.AgentID))
		}
		if node.RelayActive && node.RelayCertFingerprint == "" {
			item.Issues = appendUniqueString(item.Issues, "relay fingerprint is missing")
			item.RecoveryActions = appendUniqueString(item.RecoveryActions, fmt.Sprintf("restart relay on agent %d", node.AgentID))
		}
		if relay, ok := relaysBySession[node.SessionID]; ok {
			for _, problem := range relay.Problems {
				item.Issues = appendUniqueString(item.Issues, problem)
				item.RecoveryActions = appendUniqueString(item.RecoveryActions, fmt.Sprintf("inspect relay event history for agent %d", node.AgentID))
			}
		}
		if len(item.Issues) > 0 {
			item.State = "degraded"
		}
		if !node.Alive {
			item.State = "offline"
		}
		health = append(health, item)
	})
	return health
}

func relayMeshHealthSummary(health []RelayMeshHealth) RelayMeshHealthSummary {
	var summary RelayMeshHealthSummary
	summary.Total = len(health)
	for _, item := range health {
		switch item.State {
		case "healthy":
			summary.Healthy++
		case "offline":
			summary.Offline++
		default:
			summary.Degraded++
		}
		if len(item.RecoveryActions) > 0 {
			summary.Repairable++
		}
	}
	return summary
}

func flattenChainNodes(nodes []proxy.ChainNode) map[string]proxy.ChainNode {
	flat := make(map[string]proxy.ChainNode)
	walkChainNodes(nodes, func(node proxy.ChainNode) {
		flat[node.SessionID] = node
	})
	return flat
}

func walkChainNodes(nodes []proxy.ChainNode, visit func(proxy.ChainNode)) {
	for _, node := range nodes {
		visit(node)
		walkChainNodes(node.Children, visit)
	}
}

func appendUniqueString(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}
