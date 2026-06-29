// Ligolo-ng Relay
// Copyright (C) 2025 Nicolas Chatelain (nicocha30)

package app

import (
	"net"
	"strings"
	"testing"
	"time"

	agentpkg "github.com/allsmog/ligolo-ng-relay/pkg/agent"
	"github.com/allsmog/ligolo-ng-relay/pkg/controller"
	"github.com/allsmog/ligolo-ng-relay/pkg/protocol"
	"github.com/allsmog/ligolo-ng-relay/pkg/proxy"
	"github.com/hashicorp/yamux"
)

func TestRelayConnectCommandIncludesFingerprintAndToken(t *testing.T) {
	command := relayConnectCommand("0.0.0.0:11602", "ABCD", "relay-secret")

	if !strings.Contains(command, "-accept-fingerprint ABCD") {
		t.Fatalf("connect command missing fingerprint: %s", command)
	}
	if !strings.Contains(command, "-relay-token relay-secret") {
		t.Fatalf("connect command missing relay token: %s", command)
	}
	if !strings.Contains(command, "<relay-agent-reachable-ip>:11602") {
		t.Fatalf("connect command should use reachable placeholder for wildcard bind: %s", command)
	}
}

func TestChainRouteInfosReportsDuplicateRouteConflicts(t *testing.T) {
	resetAppTestState(t)

	AgentList[1] = &controller.LigoloAgent{
		Name:      "root@agent-a",
		SessionID: "agent-a",
		Session:   testYamuxSession(t),
		Network: []protocol.NetInterface{
			{Addresses: []string{"10.20.30.5/24"}},
		},
	}
	AgentList[2] = &controller.LigoloAgent{
		Name:      "root@agent-b",
		SessionID: "agent-b",
		Session:   testYamuxSession(t),
		Network: []protocol.NetInterface{
			{Addresses: []string{"10.20.30.8/24"}},
		},
	}

	routes := chainRouteInfos(false, "relaytest")
	if len(routes) != 2 {
		t.Fatalf("routes = %d, want 2: %+v", len(routes), routes)
	}
	for _, route := range routes {
		if !route.Conflict {
			t.Fatalf("route conflict was not flagged: %+v", route)
		}
		if len(route.ConflictWith) != 1 {
			t.Fatalf("route conflict peers = %v, want one peer", route.ConflictWith)
		}
		if route.Warning == "" {
			t.Fatalf("route warning is empty: %+v", route)
		}
	}
}

func TestRelayDoctorReportDeduplicatesWarnings(t *testing.T) {
	resetAppTestState(t)

	AgentList[1] = &controller.LigoloAgent{
		Name:      "root@agent-a",
		SessionID: "agent-a",
		Session:   testYamuxSession(t),
		Network: []protocol.NetInterface{
			{Addresses: []string{"10.20.30.5/24"}},
		},
	}
	AgentList[2] = &controller.LigoloAgent{
		Name:      "root@agent-b",
		SessionID: "agent-b",
		Session:   testYamuxSession(t),
		Network: []protocol.NetInterface{
			{Addresses: []string{"10.20.30.8/24"}},
		},
	}
	AgentList[1].RecordRelayEvent("auth_rejected", "10.0.0.5:4444", "relay auth token rejected")
	cachePathRTT("agent-a", 1)
	cachePathRTT("agent-b", 2)

	report := relayDoctorReport(false, "relaytest")
	if report.Status != "warning" {
		t.Fatalf("doctor status = %q, want warning", report.Status)
	}
	var routeWarningCount int
	var relayWarningFound bool
	for _, warning := range report.Warnings {
		if strings.Contains(warning, "advertised by multiple agents") {
			routeWarningCount++
		}
		if strings.Contains(warning, "relay auth token rejected") {
			relayWarningFound = true
		}
	}
	if routeWarningCount != 1 {
		t.Fatalf("duplicate route warning count = %d, want 1: %v", routeWarningCount, report.Warnings)
	}
	if !relayWarningFound {
		t.Fatalf("relay auth warning not found: %v", report.Warnings)
	}
}

func TestRelayOpsReportSummarizesActionsAndConflicts(t *testing.T) {
	resetAppTestState(t)

	expired := time.Now().Add(-time.Minute)
	AgentList[1] = &controller.LigoloAgent{
		Name:                 "root@agent-a",
		SessionID:            "agent-a",
		Session:              testYamuxSession(t),
		RelayActive:          true,
		RelayListenAddr:      "127.0.0.1:11602",
		RelayCertFingerprint: "ABCD",
		RelayTokenExpiresAt:  expired,
		Network: []protocol.NetInterface{
			{Addresses: []string{"10.20.30.5/24"}},
		},
	}
	AgentList[2] = &controller.LigoloAgent{
		Name:      "root@agent-b",
		SessionID: "agent-b",
		Session:   testYamuxSession(t),
		Network: []protocol.NetInterface{
			{Addresses: []string{"10.20.30.8/24"}},
		},
	}
	ChainMgr.AddLink("agent-a", "agent-b")
	cachePathRTT("agent-a", 1)
	cachePathRTT("agent-b", 2)

	report := relayOpsReport(false, "relaytest")
	if report.Status != "warning" {
		t.Fatalf("ops status = %q, want warning", report.Status)
	}
	if report.Summary.AgentsTotal != 2 {
		t.Fatalf("agents total = %d, want 2", report.Summary.AgentsTotal)
	}
	if report.Summary.AgentsOnline != 2 {
		t.Fatalf("agents online = %d, want 2", report.Summary.AgentsOnline)
	}
	if report.Summary.DirectAgents != 1 {
		t.Fatalf("direct agents = %d, want 1", report.Summary.DirectAgents)
	}
	if report.Summary.RelayedAgents != 1 {
		t.Fatalf("relayed agents = %d, want 1", report.Summary.RelayedAgents)
	}
	if report.Summary.ActiveRelays != 1 {
		t.Fatalf("active relays = %d, want 1", report.Summary.ActiveRelays)
	}
	if report.Summary.DownstreamAgents != 1 {
		t.Fatalf("downstream agents = %d, want 1", report.Summary.DownstreamAgents)
	}
	if report.Summary.ExpiredTokens != 1 {
		t.Fatalf("expired tokens = %d, want 1", report.Summary.ExpiredTokens)
	}
	if report.Summary.RouteConflicts != 2 {
		t.Fatalf("route conflicts = %d, want 2", report.Summary.RouteConflicts)
	}
	if report.Summary.RoutePlanApply != 1 {
		t.Fatalf("route plan apply = %d, want 1", report.Summary.RoutePlanApply)
	}
	if report.Summary.RoutePlanSkipped != 1 {
		t.Fatalf("route plan skipped = %d, want 1", report.Summary.RoutePlanSkipped)
	}
	if report.Summary.MeshDegraded == 0 {
		t.Fatalf("mesh degraded = 0, want expired relay token to degrade mesh health")
	}
	if report.Summary.RepairActions == 0 {
		t.Fatalf("repair actions = 0, want repair plan to expose pending actions")
	}
	if report.Summary.Warnings == 0 {
		t.Fatalf("warnings = 0, want at least one")
	}

	var rotateExpiredToken bool
	var duplicateRoute bool
	for _, action := range report.Actions {
		switch action.Title {
		case "Rotate expired relay token":
			rotateExpiredToken = true
		case "Resolve duplicate route candidate":
			duplicateRoute = true
		}
	}
	if !rotateExpiredToken {
		t.Fatalf("missing rotate expired relay token action: %+v", report.Actions)
	}
	if !duplicateRoute {
		t.Fatalf("missing duplicate route action: %+v", report.Actions)
	}
}

func TestChainRoutePlanPrefersLowerCostDuplicate(t *testing.T) {
	resetAppTestState(t)

	AgentList[1] = &controller.LigoloAgent{
		Name:      "root@agent-a",
		SessionID: "agent-a",
		Session:   testYamuxSession(t),
		Network: []protocol.NetInterface{
			{Addresses: []string{"10.20.30.5/24"}},
		},
	}
	AgentList[2] = &controller.LigoloAgent{
		Name:          "root@agent-b",
		SessionID:     "agent-b",
		ParentAgentID: "agent-a",
		Session:       testYamuxSession(t),
		Network: []protocol.NetInterface{
			{Addresses: []string{"10.20.30.8/24"}},
		},
	}
	ChainMgr.AddLink("agent-a", "agent-b")
	cachePathRTT("agent-a", 10)
	cachePathRTT("agent-b", 30)

	plan := chainRoutePlan(false, "relaytest", true)
	if plan.Status != "warning" {
		t.Fatalf("plan status = %q, want warning", plan.Status)
	}
	if plan.Summary.Apply != 1 {
		t.Fatalf("plan apply = %d, want 1", plan.Summary.Apply)
	}
	if plan.Summary.Skipped != 1 {
		t.Fatalf("plan skipped = %d, want 1", plan.Summary.Skipped)
	}
	if plan.Summary.StartTunnels != 1 {
		t.Fatalf("plan start tunnels = %d, want 1", plan.Summary.StartTunnels)
	}

	decisionsByAgent := make(map[int]ChainRouteDecision)
	for _, decision := range plan.Decisions {
		decisionsByAgent[decision.AgentID] = decision
	}
	if got := decisionsByAgent[1]; got.Decision != routeDecisionApply || !got.Preferred {
		t.Fatalf("agent 1 decision = %+v, want preferred apply", got)
	}
	if !decisionsByAgent[1].StartTunnel {
		t.Fatalf("agent 1 should include tunnel start action: %+v", decisionsByAgent[1])
	}
	if got := decisionsByAgent[2]; got.Decision != routeDecisionSkipConflict || got.Preferred {
		t.Fatalf("agent 2 decision = %+v, want skipped duplicate", got)
	}
	if !strings.Contains(decisionsByAgent[2].Reason, "preferred route cost") {
		t.Fatalf("agent 2 reason = %q, want preferred route cost", decisionsByAgent[2].Reason)
	}
}

func TestChainRepairPlanBuildsSafeAndManualActions(t *testing.T) {
	rtt := int64(7)
	routePlan := ChainRoutePlan{
		Decisions: []ChainRouteDecision{
			{
				AgentID:           1,
				Name:              "root@agent-a",
				SessionID:         "agent-a",
				Interface:         "relaytest1",
				Route:             "10.20.30.5/24",
				RouteKey:          "10.20.30.0/24",
				Decision:          routeDecisionApply,
				Preferred:         true,
				Alive:             true,
				PathRTTMS:         &rtt,
				AlreadyConfigured: false,
				StartTunnel:       true,
			},
			{
				AgentID:           2,
				Name:              "root@agent-b",
				SessionID:         "agent-b",
				Interface:         "relaytest2",
				Route:             "10.20.30.8/24",
				RouteKey:          "10.20.30.0/24",
				Decision:          routeDecisionSkipConflict,
				Alive:             true,
				AlreadyConfigured: true,
			},
		},
	}
	meshHealth := []RelayMeshHealth{
		{
			AgentID:   3,
			Name:      "root@agent-c",
			SessionID: "agent-c",
			State:     "degraded",
			Alive:     true,
			Issues:    []string{"relay auth token is expired"},
		},
	}

	plan := chainRepairPlanFromInputs(routePlan, meshHealth, true)
	if plan.Status != "warning" {
		t.Fatalf("repair status = %q, want warning", plan.Status)
	}
	if plan.Summary.Actions != 4 {
		t.Fatalf("repair actions = %d, want 4: %+v", plan.Summary.Actions, plan.Actions)
	}
	if plan.Summary.ApplySupported != 3 {
		t.Fatalf("apply supported = %d, want 3", plan.Summary.ApplySupported)
	}
	if plan.Summary.Manual != 1 {
		t.Fatalf("manual = %d, want 1", plan.Summary.Manual)
	}

	var ensureRoute, startTunnel, pruneRoute, rotateToken bool
	for _, action := range plan.Actions {
		switch action.Type {
		case repairActionEnsureRoute:
			ensureRoute = action.ApplySupported && action.Interface == "relaytest1"
		case repairActionStartTunnel:
			startTunnel = action.ApplySupported && action.AgentID == 1
		case repairActionPruneDuplicateRoute:
			pruneRoute = action.ApplySupported && action.Interface == "relaytest2"
		case repairActionRotateToken:
			rotateToken = !action.ApplySupported && action.AgentID == 3
		}
	}
	if !ensureRoute || !startTunnel || !pruneRoute || !rotateToken {
		t.Fatalf("missing repair actions: ensure=%t start=%t prune=%t rotate=%t plan=%+v", ensureRoute, startTunnel, pruneRoute, rotateToken, plan.Actions)
	}
}

func TestChainFailoverPlanRecommendsBetterParent(t *testing.T) {
	resetAppTestState(t)

	expires := time.Now().Add(time.Hour)
	AgentList[1] = &controller.LigoloAgent{
		Name:                 "root@agent-a",
		SessionID:            "agent-a",
		Session:              testYamuxSession(t),
		RelayActive:          true,
		RelayListenAddr:      "127.0.0.1:11602",
		RelayCertFingerprint: "FINGERPRINTA",
		RelayAuthToken:       "token-a",
		RelayTokenExpiresAt:  expires,
	}
	AgentList[2] = &controller.LigoloAgent{
		Name:                 "root@agent-b",
		SessionID:            "agent-b",
		Session:              testYamuxSession(t),
		RelayActive:          true,
		RelayListenAddr:      "0.0.0.0:11603",
		RelayCertFingerprint: "FINGERPRINTB",
		RelayAuthToken:       "token-b",
		RelayTokenExpiresAt:  expires,
	}
	AgentList[3] = &controller.LigoloAgent{
		Name:      "root@agent-c",
		SessionID: "agent-c",
		Session:   testYamuxSession(t),
	}
	ChainMgr.AddLink("agent-b", "agent-c")
	cachePathRTT("agent-a", 10)
	cachePathRTT("agent-b", 50)
	cachePathRTT("agent-c", 70)

	plan := chainFailoverPlan(true)
	if plan.Status != "warning" {
		t.Fatalf("failover status = %q, want warning", plan.Status)
	}
	if plan.Summary.RelayedAgents != 1 {
		t.Fatalf("relayed agents = %d, want 1", plan.Summary.RelayedAgents)
	}
	if plan.Summary.Recommendations != 1 {
		t.Fatalf("recommendations = %d, want 1: %+v", plan.Summary.Recommendations, plan.Recommendations)
	}
	rec := plan.Recommendations[0]
	if rec.SessionID != "agent-c" {
		t.Fatalf("recommendation session = %q, want agent-c", rec.SessionID)
	}
	if rec.RecommendedParent == nil || rec.RecommendedParent.SessionID != "agent-a" {
		t.Fatalf("recommended parent = %+v, want agent-a", rec.RecommendedParent)
	}
	if !rec.CommandAvailable {
		t.Fatalf("command should be available: %+v", rec)
	}
	if !rec.ApplySupported {
		t.Fatalf("apply should be supported: %+v", rec)
	}
	if rec.RecommendedParent.ReconnectAddr != "127.0.0.1:11602" {
		t.Fatalf("reconnect addr = %q, want 127.0.0.1:11602", rec.RecommendedParent.ReconnectAddr)
	}
	if !strings.Contains(rec.ConnectCommand, "-relay-token token-a") {
		t.Fatalf("connect command missing token: %s", rec.ConnectCommand)
	}
	if !strings.Contains(rec.ConnectCommand, "-accept-fingerprint FINGERPRINTA") {
		t.Fatalf("connect command missing fingerprint: %s", rec.ConnectCommand)
	}
}

func TestApplyChainFailoverPlanUpdatesReconnectTarget(t *testing.T) {
	resetAppTestState(t)

	reconnectRequests := make(chan protocol.AgentReconnectRequestPacket, 1)
	agentpkg.SetReconnectRequestHandler(func(request protocol.AgentReconnectRequestPacket) error {
		reconnectRequests <- request
		return nil
	})
	t.Cleanup(func() {
		agentpkg.SetReconnectRequestHandler(nil)
	})

	expires := time.Now().Add(time.Hour)
	AgentList[1] = &controller.LigoloAgent{
		Name:                 "root@agent-a",
		SessionID:            "agent-a",
		Session:              testYamuxSession(t),
		RelayActive:          true,
		RelayListenAddr:      "127.0.0.1:11602",
		RelayCertFingerprint: "FINGERPRINTA",
		RelayAuthToken:       "token-a",
		RelayTokenExpiresAt:  expires,
	}
	AgentList[2] = &controller.LigoloAgent{
		Name:                 "root@agent-b",
		SessionID:            "agent-b",
		Session:              testYamuxSession(t),
		RelayActive:          true,
		RelayListenAddr:      "127.0.0.1:11603",
		RelayCertFingerprint: "FINGERPRINTB",
		RelayAuthToken:       "token-b",
		RelayTokenExpiresAt:  expires,
	}
	AgentList[3] = &controller.LigoloAgent{
		Name:      "root@agent-c",
		SessionID: "agent-c",
		Session:   testYamuxSessionWithAgentHandler(t),
	}
	ChainMgr.AddLink("agent-b", "agent-c")
	cachePathRTT("agent-a", 10)
	cachePathRTT("agent-b", 50)
	cachePathRTT("agent-c", 70)

	plan := applyChainFailoverPlan(false, false, []string{"agent-c"}, nil)
	if plan.Status != "warning" {
		t.Fatalf("failover status = %q, want warning", plan.Status)
	}
	if plan.Summary.Applied != 1 || plan.Summary.Failed != 0 {
		t.Fatalf("summary applied/failed = %d/%d, want 1/0", plan.Summary.Applied, plan.Summary.Failed)
	}
	if len(plan.Recommendations) != 1 || !plan.Recommendations[0].Applied {
		t.Fatalf("recommendation not applied: %+v", plan.Recommendations)
	}

	select {
	case request := <-reconnectRequests:
		if request.ConnectAddr != "127.0.0.1:11602" {
			t.Fatalf("connect addr = %q, want 127.0.0.1:11602", request.ConnectAddr)
		}
		if request.AcceptFingerprint != "FINGERPRINTA" {
			t.Fatalf("fingerprint = %q, want FINGERPRINTA", request.AcceptFingerprint)
		}
		if request.RelayToken != "token-a" {
			t.Fatalf("relay token = %q, want token-a", request.RelayToken)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for reconnect request")
	}
}

func TestRunRelayAutoHealMonitorPlansFailoverWithoutApplying(t *testing.T) {
	resetAppTestState(t)

	reconnectRequests := make(chan protocol.AgentReconnectRequestPacket, 1)
	agentpkg.SetReconnectRequestHandler(func(request protocol.AgentReconnectRequestPacket) error {
		reconnectRequests <- request
		return nil
	})
	t.Cleanup(func() {
		agentpkg.SetReconnectRequestHandler(nil)
	})
	seedFailoverTestAgents(t, testYamuxSessionWithAgentHandler(t))

	run := runRelayAutoHeal(RelayAutoHealPolicy{
		Apply:    false,
		Repair:   false,
		Failover: true,
	})
	if run.Mode != relayAutoHealModeMonitor {
		t.Fatalf("mode = %q, want monitor", run.Mode)
	}
	if run.Applied != 0 || run.FailoverApplied != 0 {
		t.Fatalf("applied = %d/%d, want 0/0", run.Applied, run.FailoverApplied)
	}
	if run.FailoverPlan == nil || run.FailoverPlan.Summary.Recommendations != 1 {
		t.Fatalf("failover recommendations = %+v, want one recommendation", run.FailoverPlan)
	}
	select {
	case request := <-reconnectRequests:
		t.Fatalf("unexpected reconnect request in monitor mode: %+v", request)
	default:
	}
}

func TestRunRelayAutoHealApplyFailoverUpdatesReconnectTarget(t *testing.T) {
	resetAppTestState(t)

	reconnectRequests := make(chan protocol.AgentReconnectRequestPacket, 1)
	agentpkg.SetReconnectRequestHandler(func(request protocol.AgentReconnectRequestPacket) error {
		reconnectRequests <- request
		return nil
	})
	t.Cleanup(func() {
		agentpkg.SetReconnectRequestHandler(nil)
	})
	seedFailoverTestAgents(t, testYamuxSessionWithAgentHandler(t))

	run := runRelayAutoHeal(RelayAutoHealPolicy{
		Apply:        true,
		Repair:       false,
		Failover:     true,
		MaxFailovers: 1,
	})
	if run.Mode != relayAutoHealModeApply {
		t.Fatalf("mode = %q, want apply", run.Mode)
	}
	if run.FailoverApplied != 1 || run.FailoverFailed != 0 {
		t.Fatalf("failover applied/failed = %d/%d, want 1/0", run.FailoverApplied, run.FailoverFailed)
	}
	if run.Applied != 1 || run.Failed != 0 {
		t.Fatalf("run applied/failed = %d/%d, want 1/0", run.Applied, run.Failed)
	}

	select {
	case request := <-reconnectRequests:
		if request.ConnectAddr != "127.0.0.1:11602" {
			t.Fatalf("connect addr = %q, want 127.0.0.1:11602", request.ConnectAddr)
		}
		if request.AcceptFingerprint != "FINGERPRINTA" {
			t.Fatalf("fingerprint = %q, want FINGERPRINTA", request.AcceptFingerprint)
		}
		if request.RelayToken != "token-a" {
			t.Fatalf("relay token = %q, want token-a", request.RelayToken)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for reconnect request")
	}
}

func resetAppTestState(t *testing.T) {
	oldAgentList := AgentList
	oldChainMgr := ChainMgr

	AgentListMutex.Lock()
	AgentList = make(map[int]*controller.LigoloAgent)
	AgentListMutex.Unlock()
	ChainMgr = proxy.NewChainManager()

	pathRTTCache.Lock()
	oldPathRTTEntries := pathRTTCache.entries
	pathRTTCache.entries = make(map[string]pathRTTCacheEntry)
	pathRTTCache.Unlock()

	t.Cleanup(func() {
		AgentListMutex.Lock()
		AgentList = oldAgentList
		AgentListMutex.Unlock()
		ChainMgr = oldChainMgr

		pathRTTCache.Lock()
		pathRTTCache.entries = oldPathRTTEntries
		pathRTTCache.Unlock()
	})
}

func seedFailoverTestAgents(t *testing.T, agentCSession *yamux.Session) {
	t.Helper()

	expires := time.Now().Add(time.Hour)
	AgentList[1] = &controller.LigoloAgent{
		Name:                 "root@agent-a",
		SessionID:            "agent-a",
		Session:              testYamuxSession(t),
		RelayActive:          true,
		RelayListenAddr:      "127.0.0.1:11602",
		RelayCertFingerprint: "FINGERPRINTA",
		RelayAuthToken:       "token-a",
		RelayTokenExpiresAt:  expires,
	}
	AgentList[2] = &controller.LigoloAgent{
		Name:                 "root@agent-b",
		SessionID:            "agent-b",
		Session:              testYamuxSession(t),
		RelayActive:          true,
		RelayListenAddr:      "127.0.0.1:11603",
		RelayCertFingerprint: "FINGERPRINTB",
		RelayAuthToken:       "token-b",
		RelayTokenExpiresAt:  expires,
	}
	AgentList[3] = &controller.LigoloAgent{
		Name:      "root@agent-c",
		SessionID: "agent-c",
		Session:   agentCSession,
	}
	ChainMgr.AddLink("agent-b", "agent-c")
	cachePathRTT("agent-a", 10)
	cachePathRTT("agent-b", 50)
	cachePathRTT("agent-c", 70)
}

func testYamuxSession(t *testing.T) *yamux.Session {
	t.Helper()

	clientConn, serverConn := net.Pipe()
	serverSession, err := yamux.Server(serverConn, yamux.DefaultConfig())
	if err != nil {
		t.Fatalf("yamux server: %v", err)
	}
	clientSession, err := yamux.Client(clientConn, yamux.DefaultConfig())
	if err != nil {
		t.Fatalf("yamux client: %v", err)
	}
	t.Cleanup(func() {
		clientSession.Close()
		serverSession.Close()
		clientConn.Close()
		serverConn.Close()
	})
	return clientSession
}

func testYamuxSessionWithAgentHandler(t *testing.T) *yamux.Session {
	t.Helper()

	clientConn, serverConn := net.Pipe()
	serverSession, err := yamux.Server(serverConn, yamux.DefaultConfig())
	if err != nil {
		t.Fatalf("yamux server: %v", err)
	}
	clientSession, err := yamux.Client(clientConn, yamux.DefaultConfig())
	if err != nil {
		t.Fatalf("yamux client: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := serverSession.Accept()
			if err != nil {
				return
			}
			go agentpkg.HandleConn(conn)
		}
	}()
	t.Cleanup(func() {
		clientSession.Close()
		serverSession.Close()
		clientConn.Close()
		serverConn.Close()
		<-done
	})
	return clientSession
}

func cachePathRTT(sessionID string, value int64) {
	pathRTTCache.Lock()
	defer pathRTTCache.Unlock()
	pathRTTCache.entries[sessionID] = pathRTTCacheEntry{
		value:     &value,
		checkedAt: time.Now(),
	}
}
