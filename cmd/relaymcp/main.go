// Ligolo-ng Relay
// Copyright (C) 2025 Nicolas Chatelain (nicocha30)

// Command relaymcp is a Model Context Protocol (MCP) server that exposes the
// Ligolo-ng Relay proxy control plane to MCP clients (e.g. Claude). It is the
// MCP counterpart of relayctl: it authenticates to the proxy REST API and maps
// each operation to an MCP tool.
//
// It speaks MCP over stdio by default (for local clients such as Claude Code or
// Claude Desktop) or over streamable HTTP when -http is set (for a remote
// client reaching a remote proxy).
//
// All diagnostic output goes to stderr; stdout is reserved for the MCP stdio
// transport and must never be written to directly.
package main

import (
	"context"
	"crypto/subtle"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/allsmog/ligolo-ng-relay/pkg/relayapi"
	"github.com/allsmog/ligolo-ng-relay/pkg/relaymcp"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// version is overridden at link time via -ldflags "-X main.version=...".
// GoReleaser injects this by default; local `go build` reports "dev".
var version = "dev"

func main() {
	log.SetFlags(log.LstdFlags)
	log.SetPrefix("relaymcp: ")
	log.SetOutput(os.Stderr) // never write to stdout: it carries the MCP stdio stream

	apiURL := envDefault("LIGOLO_API", "http://127.0.0.1:8080")
	username := envDefault("LIGOLO_USER", "")
	password := envDefault("LIGOLO_PASSWORD", "")
	token := envDefault("LIGOLO_TOKEN", "")
	httpToken := envDefault("LIGOLO_MCP_HTTP_TOKEN", "")
	readOnly := envBool("LIGOLO_MCP_READ_ONLY", false)

	fs := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	fs.StringVar(&apiURL, "api", apiURL, "Ligolo-ng Relay API base URL (or LIGOLO_API)")
	fs.StringVar(&username, "user", username, "API username (or LIGOLO_USER)")
	fs.StringVar(&password, "password", password, "API password (or LIGOLO_PASSWORD)")
	fs.StringVar(&token, "token", token, "API bearer token (or LIGOLO_TOKEN)")
	httpAddr := fs.String("http", "", "serve MCP over streamable HTTP on this address (e.g. 127.0.0.1:9090); stdio when empty")
	fs.StringVar(&httpToken, "http-token", httpToken, "bearer token required for the HTTP transport (or LIGOLO_MCP_HTTP_TOKEN)")
	tlsCert := fs.String("tls-cert", "", "TLS certificate file for the HTTP transport")
	tlsKey := fs.String("tls-key", "", "TLS key file for the HTTP transport")
	fs.BoolVar(&readOnly, "read-only", readOnly, "expose only read-only diagnostic tools (or LIGOLO_MCP_READ_ONLY)")
	showVersion := fs.Bool("version", false, "print version and exit")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "relaymcp - MCP server for Ligolo-ng Relay\n\nUsage: relaymcp [flags]\n\nFlags:\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(os.Args[1:]); err != nil {
		log.Fatal(err)
	}

	if *showVersion {
		// Safe to use stdout here: we are not running the stdio transport.
		fmt.Printf("relaymcp %s\n", version)
		return
	}

	client := relayapi.New(relayapi.Config{
		BaseURL:  apiURL,
		Username: username,
		Password: password,
		Token:    token,
	})
	backend := relaymcp.NewRESTBackend(client)
	server := relaymcp.NewMCPServer(backend, relaymcp.ServerOptions{
		ReadOnly: readOnly,
		Version:  version,
	})

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	mode := "read-write"
	if readOnly {
		mode = "read-only"
	}

	var err error
	if *httpAddr != "" {
		log.Printf("serving MCP over streamable HTTP on %s (%s), proxy API %s", *httpAddr, mode, client.BaseURL())
		err = serveHTTP(ctx, server, *httpAddr, httpToken, *tlsCert, *tlsKey)
	} else {
		log.Printf("serving MCP over stdio (%s), proxy API %s", mode, client.BaseURL())
		err = server.Run(ctx, &mcp.StdioTransport{})
	}
	if err != nil && !errors.Is(err, context.Canceled) {
		log.Fatal(err)
	}
}

func serveHTTP(ctx context.Context, server *mcp.Server, addr, token, tlsCert, tlsKey string) error {
	if token == "" && !isLoopbackBind(addr) {
		return fmt.Errorf("refusing to expose the MCP server on non-loopback address %q without a bearer token: set -http-token / LIGOLO_MCP_HTTP_TOKEN, or bind to 127.0.0.1", addr)
	}
	if (tlsCert == "") != (tlsKey == "") {
		return errors.New("-tls-cert and -tls-key must be set together")
	}

	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server {
		return server
	}, nil)

	srv := &http.Server{
		Addr:              addr,
		Handler:           bearerAuth(handler, token),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	var err error
	if tlsCert != "" {
		err = srv.ListenAndServeTLS(tlsCert, tlsKey)
	} else {
		err = srv.ListenAndServe()
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// bearerAuth requires Authorization: Bearer <token> (a bare token is also
// accepted) when token is non-empty. When token is empty it is a no-op, which
// is only permitted for loopback binds (enforced by serveHTTP).
func bearerAuth(next http.Handler, token string) http.Handler {
	if token == "" {
		return next
	}
	want := []byte(token)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		if subtle.ConstantTimeCompare([]byte(got), want) != 1 {
			w.Header().Set("WWW-Authenticate", "Bearer")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func isLoopbackBind(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	switch host {
	case "localhost":
		return true
	case "", "0.0.0.0", "::":
		// Empty host or wildcard binds all interfaces — not loopback-only.
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

func envDefault(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func envBool(key string, fallback bool) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(key))) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return fallback
	}
}
