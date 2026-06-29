// Ligolo-ng Relay
// Copyright (C) 2025 Nicolas Chatelain (nicocha30)

// Package relayapi is a small authenticated HTTP client for the Ligolo-ng
// Relay proxy REST API (POST /api/auth -> JWT, then Bearer-authenticated
// /api/v1 calls). It is shared by the relayctl CLI and the relaymcp MCP
// server so both speak to the proxy the same way.
package relayapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// DefaultTimeout is the per-request timeout used when Config.HTTPClient is nil.
const DefaultTimeout = 15 * time.Second

// Config configures a Client. Either Token, or Username+Password, must be set
// for authenticated requests to succeed.
type Config struct {
	BaseURL    string
	Username   string
	Password   string
	Token      string
	HTTPClient *http.Client
}

// Client issues authenticated requests against the relay proxy API. It is safe
// for concurrent use: the cached JWT is guarded by a mutex so a long-lived
// server (the MCP bridge) can refresh it transparently when it expires.
type Client struct {
	baseURL    string
	username   string
	password   string
	httpClient *http.Client

	mu    sync.Mutex
	token string
}

// New builds a Client from cfg, defaulting the HTTP client when unset.
func New(cfg Config) *Client {
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: DefaultTimeout}
	}
	return &Client{
		baseURL:    strings.TrimRight(cfg.BaseURL, "/"),
		username:   cfg.Username,
		password:   cfg.Password,
		token:      cfg.Token,
		httpClient: httpClient,
	}
}

// BaseURL returns the normalized API base URL.
func (c *Client) BaseURL() string { return c.baseURL }

func (c *Client) currentToken() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.token
}

func (c *Client) setToken(token string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.token = token
}

func (c *Client) canRefresh() bool {
	return c.username != "" && c.password != ""
}

// Do performs an authenticated request and returns the raw response body.
//
// If no token is cached yet it authenticates first. If the server answers 401
// (the JWT has a ~1h TTL), it re-authenticates once and retries — so a
// long-running MCP server keeps working across token expiries without restart.
func (c *Client) Do(ctx context.Context, method, path string, body any) (json.RawMessage, error) {
	if c.currentToken() == "" {
		if err := c.authenticate(ctx); err != nil {
			return nil, err
		}
	}

	payload, status, err := c.doOnce(ctx, method, path, body)
	if err != nil {
		return nil, err
	}

	if status == http.StatusUnauthorized && c.canRefresh() {
		if err := c.authenticate(ctx); err != nil {
			return nil, err
		}
		payload, status, err = c.doOnce(ctx, method, path, body)
		if err != nil {
			return nil, err
		}
	}

	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("%s %s failed: HTTP %d: %s", method, path, status, strings.TrimSpace(string(payload)))
	}
	return payload, nil
}

func (c *Client) doOnce(ctx context.Context, method, path string, body any) ([]byte, int, error) {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return nil, 0, err
		}
		reader = bytes.NewReader(encoded)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return nil, 0, err
	}
	if token := c.currentToken(); token != "" {
		// The proxy accepts either "Bearer <jwt>" or a bare token; send the
		// value verbatim so a user-supplied LIGOLO_TOKEN is passed through as-is.
		req.Header.Set("Authorization", token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	payload, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, 0, err
	}
	return payload, resp.StatusCode, nil
}

func (c *Client) authenticate(ctx context.Context) error {
	if !c.canRefresh() {
		return errors.New("not authenticated: set a token, or a username and password")
	}
	body, err := json.Marshal(map[string]string{
		"Username": c.username,
		"Password": c.password,
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/auth", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("auth failed: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	var authResp struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(data, &authResp); err != nil {
		return err
	}
	if authResp.Token == "" {
		return errors.New("auth response did not include a token")
	}
	c.setToken(authResp.Token)
	return nil
}
