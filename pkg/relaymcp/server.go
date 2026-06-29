// Ligolo-ng Relay
// Copyright (C) 2025 Nicolas Chatelain (nicocha30)

package relaymcp

import "github.com/modelcontextprotocol/go-sdk/mcp"

// Version is the server version reported to MCP clients. The binary's main may
// override it (e.g. from the build stamp).
var Version = "dev"

// ServerOptions configures the MCP server.
type ServerOptions struct {
	// ReadOnly omits every mutating tool, exposing a pure diagnostics surface.
	ReadOnly bool
	// Version overrides the reported server version when non-empty.
	Version string
}

// NewMCPServer builds an MCP server that exposes the Ligolo-ng Relay control
// plane through the given backend.
func NewMCPServer(backend RelayBackend, opts ServerOptions) *mcp.Server {
	version := opts.Version
	if version == "" {
		version = Version
	}
	server := mcp.NewServer(&mcp.Implementation{
		Name:    "ligolo-ng-relay",
		Title:   "Ligolo-ng Relay",
		Version: version,
	}, nil)
	registerTools(server, backend, opts.ReadOnly)
	return server
}
