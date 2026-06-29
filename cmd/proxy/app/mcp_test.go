// Ligolo-ng Relay
// Copyright (C) 2025 Nicolas Chatelain (nicocha30)

package app

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/allsmog/ligolo-ng-relay/pkg/relaymcp"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// connectInProc wires an in-memory MCP client to a server backed by the
// in-process backend, exercising the embedded (proxy -mcp) path.
func connectInProc(t *testing.T, readOnly bool) *mcp.ClientSession {
	t.Helper()
	server := relaymcp.NewMCPServer(inProcBackend{}, relaymcp.ServerOptions{ReadOnly: readOnly})
	ctx := context.Background()
	st, ct := mcp.NewInMemoryTransports()
	if _, err := server.Connect(ctx, st, nil); err != nil {
		t.Fatalf("server connect: %v", err)
	}
	session, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "v0"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })
	return session
}

// TestInProcBackendServesMCP proves the embedded MCP server registers all tools
// (in-proc backend satisfies the schema/registration path) and answers tool
// calls that need no agent state.
func TestInProcBackendServesMCP(t *testing.T) {
	session := connectInProc(t, false)
	ctx := context.Background()

	tools, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}
	if len(tools.Tools) != 28 {
		t.Fatalf("tool count = %d, want 28", len(tools.Tools))
	}

	res, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "ping"})
	if err != nil {
		t.Fatalf("call ping: %v", err)
	}
	if res.IsError {
		t.Fatal("ping returned tool error")
	}
	text := res.Content[0].(*mcp.TextContent).Text
	if text != `{"message":"pong"}` {
		t.Fatalf("ping = %q, want pong message", text)
	}

	// list_agents must return valid JSON regardless of current agent state.
	res, err = session.CallTool(ctx, &mcp.CallToolParams{Name: "list_agents"})
	if err != nil || res.IsError {
		t.Fatalf("call list_agents: err=%v isErr=%v", err, res.IsError)
	}
	var v any
	if err := json.Unmarshal([]byte(res.Content[0].(*mcp.TextContent).Text), &v); err != nil {
		t.Fatalf("list_agents returned invalid JSON: %v", err)
	}
}

func TestInProcBackendReadOnlyDropsMutators(t *testing.T) {
	session := connectInProc(t, true)
	tools, err := session.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}
	if len(tools.Tools) != 12 {
		t.Fatalf("read-only tool count = %d, want 12", len(tools.Tools))
	}
}
