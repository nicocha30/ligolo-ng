// Ligolo-ng Relay
// Copyright (C) 2025 Nicolas Chatelain (nicocha30)

package relaymcp

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/allsmog/ligolo-ng-relay/pkg/relayapi"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// recordedRequest captures what the mock proxy API received for one call.
type recordedRequest struct {
	Method   string
	Path     string
	RawQuery string
	Body     []byte
}

type mockAPI struct {
	mu   sync.Mutex
	last recordedRequest
}

func (m *mockAPI) record(r recordedRequest) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.last = r
}

func (m *mockAPI) lastRequest() recordedRequest {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.last
}

// newTestServer wires a mock proxy API to a relaymcp MCP server and returns a
// connected in-memory client session plus the request recorder.
func newTestServer(t *testing.T, opts ServerOptions) (*mcp.ClientSession, *mockAPI) {
	t.Helper()

	api := &mockAPI{}
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		api.record(recordedRequest{Method: r.Method, Path: r.URL.Path, RawQuery: r.URL.RawQuery, Body: body})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(httpServer.Close)

	client := relayapi.New(relayapi.Config{
		BaseURL:    httpServer.URL,
		Token:      "test-token", // skip the /api/auth round-trip
		HTTPClient: httpServer.Client(),
	})
	server := NewMCPServer(NewRESTBackend(client), opts)

	ctx := context.Background()
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	if _, err := server.Connect(ctx, serverTransport, nil); err != nil {
		t.Fatalf("server connect: %v", err)
	}
	mcpClient := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "v0.0.1"}, nil)
	session, err := mcpClient.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })
	return session, api
}

func callTool(t *testing.T, session *mcp.ClientSession, name string, args map[string]any) *mcp.CallToolResult {
	t.Helper()
	res, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("call %s: %v", name, err)
	}
	if res.IsError {
		t.Fatalf("call %s returned tool error: %s", name, resultText(t, res))
	}
	return res
}

func resultText(t *testing.T, res *mcp.CallToolResult) string {
	t.Helper()
	if len(res.Content) == 0 {
		t.Fatal("result has no content")
	}
	tc, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("content is %T, want *mcp.TextContent", res.Content[0])
	}
	return tc.Text
}

func decodeBody(t *testing.T, body []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("decode body %q: %v", string(body), err)
	}
	return m
}

// TestNewMCPServerRegistersTools ensures every AddTool call succeeds (schema
// inference does not panic) and that read-only mode drops the mutating tools.
func TestNewMCPServerRegistersTools(t *testing.T) {
	t.Run("read-write", func(t *testing.T) {
		session, _ := newTestServer(t, ServerOptions{})
		names := toolNames(t, session)
		if len(names) != 28 {
			t.Fatalf("read-write tool count = %d, want 28: %v", len(names), names)
		}
		for _, want := range []string{"list_agents", "relay_ops", "relay_start", "tunnel_stop", "add_route"} {
			if !names[want] {
				t.Fatalf("missing tool %q", want)
			}
		}
	})

	t.Run("read-only", func(t *testing.T) {
		session, _ := newTestServer(t, ServerOptions{ReadOnly: true})
		names := toolNames(t, session)
		if len(names) != 12 {
			t.Fatalf("read-only tool count = %d, want 12: %v", len(names), names)
		}
		for _, mutating := range []string{"relay_start", "relay_stop", "tunnel_start", "chain_repair_apply", "delete_route"} {
			if names[mutating] {
				t.Fatalf("mutating tool %q exposed in read-only mode", mutating)
			}
		}
	})
}

func toolNames(t *testing.T, session *mcp.ClientSession) map[string]bool {
	t.Helper()
	res, err := session.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}
	names := make(map[string]bool, len(res.Tools))
	for _, tool := range res.Tools {
		names[tool.Name] = true
	}
	return names
}

func TestReadOnlyModeRejectsMutatingCall(t *testing.T) {
	session, _ := newTestServer(t, ServerOptions{ReadOnly: true})
	_, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "relay_stop",
		Arguments: map[string]any{"agent_id": 1},
	})
	if err == nil {
		t.Fatal("calling relay_stop in read-only mode succeeded, want error")
	}
}

func TestListAgentsTool(t *testing.T) {
	session, api := newTestServer(t, ServerOptions{})
	res := callTool(t, session, "list_agents", nil)
	if got := resultText(t, res); got != `{"ok":true}` {
		t.Fatalf("result = %q, want canned JSON", got)
	}
	req := api.lastRequest()
	if req.Method != http.MethodGet || req.Path != "/api/v1/agents" {
		t.Fatalf("request = %s %s, want GET /api/v1/agents", req.Method, req.Path)
	}
}

func TestRelayOpsToolForwardsQuery(t *testing.T) {
	session, api := newTestServer(t, ServerOptions{})
	callTool(t, session, "relay_ops", map[string]any{"with_ipv6": true, "interface_prefix": "relaytest"})
	req := api.lastRequest()
	if req.Method != http.MethodGet || req.Path != "/api/v1/relay/ops" {
		t.Fatalf("request = %s %s, want GET /api/v1/relay/ops", req.Method, req.Path)
	}
	if req.RawQuery != "interface_prefix=relaytest&with_ipv6=true" {
		t.Fatalf("query = %q", req.RawQuery)
	}
}

func TestDiagToolDefaultsInterfacePrefix(t *testing.T) {
	session, api := newTestServer(t, ServerOptions{})
	callTool(t, session, "relay_doctor", nil)
	req := api.lastRequest()
	if req.RawQuery != "interface_prefix=ligolo&with_ipv6=false" {
		t.Fatalf("query = %q, want default ligolo prefix", req.RawQuery)
	}
}

func TestRelayStartToolPostsBody(t *testing.T) {
	session, api := newTestServer(t, ServerOptions{})
	callTool(t, session, "relay_start", map[string]any{
		"agent_id":          7,
		"listen_addr":       "0.0.0.0:11602",
		"token_ttl_seconds": 1800,
		"one_time_token":    true,
	})
	req := api.lastRequest()
	if req.Method != http.MethodPost || req.Path != "/api/v1/relay/7" {
		t.Fatalf("request = %s %s, want POST /api/v1/relay/7", req.Method, req.Path)
	}
	body := decodeBody(t, req.Body)
	if body["ListenAddr"] != "0.0.0.0:11602" {
		t.Fatalf("ListenAddr = %v", body["ListenAddr"])
	}
	if body["TokenTTLSeconds"].(float64) != 1800 {
		t.Fatalf("TokenTTLSeconds = %v", body["TokenTTLSeconds"])
	}
	if body["OneTimeToken"] != true {
		t.Fatalf("OneTimeToken = %v", body["OneTimeToken"])
	}
}

func TestTunnelStopToolDeletes(t *testing.T) {
	session, api := newTestServer(t, ServerOptions{})
	callTool(t, session, "tunnel_stop", map[string]any{"agent_id": 3})
	req := api.lastRequest()
	if req.Method != http.MethodDelete || req.Path != "/api/v1/tunnel/3" {
		t.Fatalf("request = %s %s, want DELETE /api/v1/tunnel/3", req.Method, req.Path)
	}
}

func TestAddRouteToolPostsRoutes(t *testing.T) {
	session, api := newTestServer(t, ServerOptions{})
	callTool(t, session, "add_route", map[string]any{
		"interface": "ligolo0",
		"routes":    []any{"10.0.0.0/24", "10.1.0.0/24"},
	})
	req := api.lastRequest()
	if req.Method != http.MethodPost || req.Path != "/api/v1/routes" {
		t.Fatalf("request = %s %s, want POST /api/v1/routes", req.Method, req.Path)
	}
	body := decodeBody(t, req.Body)
	if body["Interface"] != "ligolo0" {
		t.Fatalf("Interface = %v", body["Interface"])
	}
	routes, ok := body["Route"].([]any)
	if !ok || len(routes) != 2 || routes[0] != "10.0.0.0/24" {
		t.Fatalf("Route = %v", body["Route"])
	}
}

func TestChainFailoverApplyTool(t *testing.T) {
	session, api := newTestServer(t, ServerOptions{})
	callTool(t, session, "chain_failover_apply", map[string]any{
		"all":              true,
		"include_commands": true,
	})
	req := api.lastRequest()
	if req.Method != http.MethodPost || req.Path != "/api/v1/chain_failover" {
		t.Fatalf("request = %s %s, want POST /api/v1/chain_failover", req.Method, req.Path)
	}
	body := decodeBody(t, req.Body)
	if body["All"] != true || body["IncludeCommands"] != true {
		t.Fatalf("body = %v, want All and IncludeCommands true", body)
	}
}

// TestAutohealRunToolOmitsUnsetFields verifies the pointer-override semantics:
// only fields the caller supplied are sent, so unset toggles preserve the
// proxy's configured policy.
func TestAutohealRunToolOmitsUnsetFields(t *testing.T) {
	session, api := newTestServer(t, ServerOptions{})
	callTool(t, session, "autoheal_run", map[string]any{
		"apply":  true,
		"repair": false,
	})
	req := api.lastRequest()
	if req.Method != http.MethodPost || req.Path != "/api/v1/relay/autoheal/run" {
		t.Fatalf("request = %s %s, want POST /api/v1/relay/autoheal/run", req.Method, req.Path)
	}
	body := decodeBody(t, req.Body)
	if body["Apply"] != true {
		t.Fatalf("Apply = %v, want true", body["Apply"])
	}
	if body["Repair"] != false {
		t.Fatalf("Repair = %v, want false", body["Repair"])
	}
	if _, present := body["Failover"]; present {
		t.Fatalf("Failover should be omitted when unset, got %v", body["Failover"])
	}
	if _, present := body["WithIPv6"]; present {
		t.Fatalf("WithIPv6 should be omitted when unset, got %v", body["WithIPv6"])
	}
}

func TestToolSurfacesBackendError(t *testing.T) {
	// A mock API that always 500s so the tool reports an error to the model.
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"boom"}`))
	}))
	t.Cleanup(httpServer.Close)
	client := relayapi.New(relayapi.Config{BaseURL: httpServer.URL, Token: "t", HTTPClient: httpServer.Client()})
	server := NewMCPServer(NewRESTBackend(client), ServerOptions{})

	ctx := context.Background()
	st, ct := mcp.NewInMemoryTransports()
	if _, err := server.Connect(ctx, st, nil); err != nil {
		t.Fatalf("server connect: %v", err)
	}
	session, err := mcp.NewClient(&mcp.Implementation{Name: "t", Version: "v0"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })

	res, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "list_agents"})
	if err != nil {
		t.Fatalf("call list_agents: %v", err)
	}
	if !res.IsError {
		t.Fatal("expected IsError for a 500 backend response")
	}
}

// TestAllToolsHitExpectedEndpoints calls every one of the 28 tools and asserts
// it issues the correct HTTP method and path — guarding against any path/verb
// typo in the REST backend for tools not individually covered above.
func TestAllToolsHitExpectedEndpoints(t *testing.T) {
	session, api := newTestServer(t, ServerOptions{})

	cases := []struct {
		tool   string
		args   map[string]any
		method string
		path   string
	}{
		// read-only
		{"ping", nil, "GET", "/api/v1/ping"},
		{"list_agents", nil, "GET", "/api/v1/agents"},
		{"get_chains", nil, "GET", "/api/v1/chains"},
		{"relay_doctor", nil, "GET", "/api/v1/relay/doctor"},
		{"relay_ops", nil, "GET", "/api/v1/relay/ops"},
		{"autoheal_status", nil, "GET", "/api/v1/relay/autoheal"},
		{"list_chain_routes", nil, "GET", "/api/v1/chain_routes"},
		{"chain_route_plan", nil, "GET", "/api/v1/chain_route_plan"},
		{"chain_repair_plan", nil, "GET", "/api/v1/chain_repair_plan"},
		{"chain_failover_plan", nil, "GET", "/api/v1/chain_failover_plan"},
		{"list_listeners", nil, "GET", "/api/v1/listeners"},
		{"list_interfaces", nil, "GET", "/api/v1/interfaces"},
		// mutating
		{"autoheal_run", map[string]any{"apply": false}, "POST", "/api/v1/relay/autoheal/run"},
		{"chain_autoroute", nil, "POST", "/api/v1/chain_autoroute"},
		{"chain_repair_apply", nil, "POST", "/api/v1/chain_repair"},
		{"chain_failover_apply", map[string]any{"all": true}, "POST", "/api/v1/chain_failover"},
		{"relay_start", map[string]any{"agent_id": 5}, "POST", "/api/v1/relay/5"},
		{"relay_stop", map[string]any{"agent_id": 5}, "DELETE", "/api/v1/relay/5"},
		{"relay_token_rotate", map[string]any{"agent_id": 5}, "POST", "/api/v1/relay/5/token"},
		{"relay_token_revoke", map[string]any{"agent_id": 5}, "DELETE", "/api/v1/relay/5/token"},
		{"tunnel_start", map[string]any{"agent_id": 5, "interface": "ligolo"}, "POST", "/api/v1/tunnel/5"},
		{"tunnel_stop", map[string]any{"agent_id": 5}, "DELETE", "/api/v1/tunnel/5"},
		{"create_listener", map[string]any{"agent_id": 5, "listener_addr": "0.0.0.0:8080", "redirect_addr": "127.0.0.1:9000"}, "POST", "/api/v1/listeners"},
		{"delete_listener", map[string]any{"agent_id": 5, "listener_id": 2}, "DELETE", "/api/v1/listeners"},
		{"create_interface", map[string]any{"interface": "ligolo0"}, "POST", "/api/v1/interfaces"},
		{"delete_interface", map[string]any{"interface": "ligolo0"}, "DELETE", "/api/v1/interfaces"},
		{"add_route", map[string]any{"interface": "ligolo0", "routes": []any{"10.0.0.0/24"}}, "POST", "/api/v1/routes"},
		{"delete_route", map[string]any{"interface": "ligolo0", "route": "10.0.0.0/24"}, "DELETE", "/api/v1/routes"},
	}

	if len(cases) != 28 {
		t.Fatalf("test table covers %d tools, want 28", len(cases))
	}

	for _, tc := range cases {
		t.Run(tc.tool, func(t *testing.T) {
			callTool(t, session, tc.tool, tc.args)
			req := api.lastRequest()
			if req.Method != tc.method || req.Path != tc.path {
				t.Fatalf("%s issued %s %s, want %s %s", tc.tool, req.Method, req.Path, tc.method, tc.path)
			}
		})
	}
}
