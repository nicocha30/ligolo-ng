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

package proxy

import (
	"fmt"
	"sort"
	"sync"
	"time"
)

// MaxChainDepth is the maximum number of agents allowed in a relay chain branch,
// including the direct root agent.
const MaxChainDepth = 5

// ChainManager tracks the relay topology between agents.
type ChainManager struct {
	mu    sync.Mutex
	links map[string]string // downstream SessionID -> relay agent SessionID
}

// NewChainManager creates a new ChainManager.
func NewChainManager() *ChainManager {
	return &ChainManager{
		links: make(map[string]string),
	}
}

// AddLink records that a downstream agent is connected through a relay agent.
func (cm *ChainManager) AddLink(relaySessionID, downstreamSessionID string) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.links[downstreamSessionID] = relaySessionID
}

// RemoveAgent removes an agent from the chain tracking.
func (cm *ChainManager) RemoveAgent(sessionID string) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	removed := map[string]bool{sessionID: true}
	for {
		changed := false
		for child, parent := range cm.links {
			if removed[child] || removed[parent] {
				delete(cm.links, child)
				if !removed[child] {
					removed[child] = true
					changed = true
				}
			}
		}
		if !changed {
			break
		}
	}
}

// GetParentSessionID returns the relay agent's SessionID for a downstream agent,
// or empty string if the agent is directly connected.
func (cm *ChainManager) GetParentSessionID(sessionID string) string {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	return cm.links[sessionID]
}

// GetChainPath returns the ordered list of SessionIDs from the proxy to the given agent.
// The last element is the agent itself. Returns nil if the agent is directly connected.
func (cm *ChainManager) GetChainPath(sessionID string) []string {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	var path []string
	current := sessionID
	visited := make(map[string]bool)

	for {
		if visited[current] {
			// Circular chain detected, break
			break
		}
		visited[current] = true
		path = append([]string{current}, path...)

		parent, ok := cm.links[current]
		if !ok {
			break
		}
		current = parent
	}

	if len(path) <= 1 {
		return nil // Direct connection
	}
	return path
}

// GetChainDepth returns the number of hops from the proxy to the given agent.
// Direct connections return 0.
func (cm *ChainManager) GetChainDepth(sessionID string) int {
	path := cm.GetChainPath(sessionID)
	if path == nil {
		return 0
	}
	return len(path) - 1
}

// WouldExceedMaxDepth checks if adding a downstream agent through the given
// relay agent would exceed the maximum chain depth.
func (cm *ChainManager) WouldExceedMaxDepth(relaySessionID string) bool {
	return cm.GetChainDepth(relaySessionID)+1 >= MaxChainDepth
}

// IsCircular checks if adding a link from relaySessionID to downstreamSessionID
// would create a circular chain. It walks up the chain from the relay agent's
// parent to see if the downstream agent is already an ancestor. This only
// detects actual graph cycles, not duplicate SessionIDs on the same machine.
func (cm *ChainManager) IsCircular(relaySessionID, downstreamSessionID string) bool {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	// Walk up from the relay agent's parent (not the relay itself)
	current, ok := cm.links[relaySessionID]
	if !ok {
		return false // relay is directly connected, no cycle possible
	}

	visited := make(map[string]bool)
	for {
		if current == downstreamSessionID {
			return true
		}
		if visited[current] {
			break
		}
		visited[current] = true
		parent, ok := cm.links[current]
		if !ok {
			break
		}
		current = parent
	}
	return false
}

// GetDownstreamSessionIDs returns all SessionIDs of agents connected through the given relay.
func (cm *ChainManager) GetDownstreamSessionIDs(relaySessionID string) []string {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	var downstream []string
	for child, parent := range cm.links {
		if parent == relaySessionID {
			downstream = append(downstream, child)
		}
	}
	return downstream
}

// GetDescendantSessionIDs returns every downstream SessionID reachable through
// the given relay, including nested downstream agents.
func (cm *ChainManager) GetDescendantSessionIDs(relaySessionID string) []string {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	var descendants []string
	var walk func(parent string)
	walk = func(parent string) {
		for child, linkParent := range cm.links {
			if linkParent == parent {
				descendants = append(descendants, child)
				walk(child)
			}
		}
	}
	walk(relaySessionID)
	sort.Strings(descendants)
	return descendants
}

// AgentInfo is a minimal interface for rendering the chain tree.
type AgentInfo struct {
	AgentID              int
	Name                 string
	SessionID            string
	RemoteAddr           string
	RelayActive          bool
	RelayListenAddr      string
	RelayCertFingerprint string
	RelayTokenExpiresAt  *time.Time
	RelayTokenExpired    bool
	RelayOneTimeToken    bool
	Alive                bool
	PathRTTMS            *int64
	Running              bool
	ParentSessionID      string
}

type ChainNode struct {
	AgentID              int         `json:"agent_id"`
	Name                 string      `json:"name"`
	SessionID            string      `json:"session_id"`
	RemoteAddr           string      `json:"remote_addr"`
	ParentSessionID      string      `json:"parent_session_id"`
	HopDepth             int         `json:"hop_depth"`
	Alive                bool        `json:"alive"`
	State                string      `json:"state"`
	PathRTTMS            *int64      `json:"path_rtt_ms,omitempty"`
	TunnelRunning        bool        `json:"tunnel_running"`
	RelayActive          bool        `json:"relay_active"`
	RelayListenAddr      string      `json:"relay_listen_addr"`
	RelayCertFingerprint string      `json:"relay_fingerprint,omitempty"`
	RelayTokenExpiresAt  *time.Time  `json:"relay_token_expires_at,omitempty"`
	RelayTokenExpired    bool        `json:"relay_token_expired"`
	RelayOneTimeToken    bool        `json:"relay_one_time_token"`
	DownstreamCount      int         `json:"downstream_count"`
	Children             []ChainNode `json:"children,omitempty"`
}

type ChainSnapshot struct {
	Topology string      `json:"topology"`
	MaxDepth int         `json:"max_depth"`
	Agents   []ChainNode `json:"agents"`
}

// RenderTree returns a string representation of the chain topology tree.
func (cm *ChainManager) RenderTree(agents []AgentInfo) string {
	return cm.Snapshot(agents).Topology
}

func (cm *ChainManager) Snapshot(agents []AgentInfo) ChainSnapshot {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	var roots []AgentInfo
	agentMap := make(map[string]AgentInfo)
	for _, a := range agents {
		if parent, ok := cm.links[a.SessionID]; ok {
			a.ParentSessionID = parent
		}
		agentMap[a.SessionID] = a
		if _, hasParent := cm.links[a.SessionID]; !hasParent {
			roots = append(roots, a)
		}
	}
	sort.Slice(roots, func(i, j int) bool {
		return roots[i].AgentID < roots[j].AgentID
	})

	var topology string
	if len(roots) == 0 {
		topology = "No agents connected."
	} else {
		topology = "Chain topology:\n  Proxy\n"
		for i, root := range roots {
			isLast := i == len(roots)-1
			topology += cm.renderNode(root, agentMap, "  ", isLast)
		}
	}

	nodes := make([]ChainNode, 0, len(roots))
	for _, root := range roots {
		nodes = append(nodes, cm.buildNode(root, agentMap))
	}
	return ChainSnapshot{
		Topology: topology,
		MaxDepth: MaxChainDepth,
		Agents:   nodes,
	}
}

func (cm *ChainManager) renderNode(agent AgentInfo, agentMap map[string]AgentInfo, prefix string, isLast bool) string {
	connector := "├── "
	childPrefix := prefix + "│   "
	if isLast {
		connector = "└── "
		childPrefix = prefix + "    "
	}

	status := "[direct]"
	if _, hasParent := cm.links[agent.SessionID]; hasParent {
		depth := 0
		current := agent.SessionID
		for {
			parent, ok := cm.links[current]
			if !ok {
				break
			}
			depth++
			current = parent
		}
		status = fmt.Sprintf("[%d hop(s)]", depth)
	}

	relayInfo := ""
	if agent.RelayActive {
		relayInfo = " (relay: active)"
	}
	aliveInfo := " [offline]"
	if agent.Alive {
		aliveInfo = " [online]"
	}

	result := fmt.Sprintf("%s%s%s %s%s%s\n", prefix, connector, agent.Name, status, aliveInfo, relayInfo)

	// Find children
	var children []AgentInfo
	for child, parent := range cm.links {
		if parent == agent.SessionID {
			if a, ok := agentMap[child]; ok {
				children = append(children, a)
			}
		}
	}
	sort.Slice(children, func(i, j int) bool {
		return children[i].AgentID < children[j].AgentID
	})

	for i, child := range children {
		isLastChild := i == len(children)-1
		result += cm.renderNode(child, agentMap, childPrefix, isLastChild)
	}

	return result
}

func (cm *ChainManager) buildNode(agent AgentInfo, agentMap map[string]AgentInfo) ChainNode {
	state := "offline"
	if agent.Alive {
		state = "online"
	}
	children := cm.childrenFor(agent.SessionID, agentMap)
	node := ChainNode{
		AgentID:              agent.AgentID,
		Name:                 agent.Name,
		SessionID:            agent.SessionID,
		RemoteAddr:           agent.RemoteAddr,
		ParentSessionID:      agent.ParentSessionID,
		HopDepth:             cm.depthLocked(agent.SessionID),
		Alive:                agent.Alive,
		State:                state,
		PathRTTMS:            agent.PathRTTMS,
		TunnelRunning:        agent.Running,
		RelayActive:          agent.RelayActive,
		RelayListenAddr:      agent.RelayListenAddr,
		RelayCertFingerprint: agent.RelayCertFingerprint,
		RelayTokenExpiresAt:  agent.RelayTokenExpiresAt,
		RelayTokenExpired:    agent.RelayTokenExpired,
		RelayOneTimeToken:    agent.RelayOneTimeToken,
		DownstreamCount:      len(children),
	}
	for _, child := range children {
		node.Children = append(node.Children, cm.buildNode(child, agentMap))
	}
	return node
}

func (cm *ChainManager) childrenFor(sessionID string, agentMap map[string]AgentInfo) []AgentInfo {
	var children []AgentInfo
	for child, parent := range cm.links {
		if parent == sessionID {
			if a, ok := agentMap[child]; ok {
				a.ParentSessionID = parent
				children = append(children, a)
			}
		}
	}
	sort.Slice(children, func(i, j int) bool {
		return children[i].AgentID < children[j].AgentID
	})
	return children
}

func (cm *ChainManager) depthLocked(sessionID string) int {
	depth := 0
	current := sessionID
	visited := make(map[string]bool)
	for {
		parent, ok := cm.links[current]
		if !ok || visited[current] {
			return depth
		}
		visited[current] = true
		depth++
		current = parent
	}
}
