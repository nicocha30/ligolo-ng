// Ligolo-ng
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
	"sync"
)

// MaxChainDepth is the maximum number of hops allowed in a relay chain.
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
	delete(cm.links, sessionID)
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

// AgentInfo is a minimal interface for rendering the chain tree.
type AgentInfo struct {
	Name        string
	SessionID   string
	RelayActive bool
	Alive       bool
}

// RenderTree returns a string representation of the chain topology tree.
func (cm *ChainManager) RenderTree(agents []AgentInfo) string {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	// Find root agents (directly connected)
	var roots []AgentInfo
	agentMap := make(map[string]AgentInfo)
	for _, a := range agents {
		agentMap[a.SessionID] = a
		if _, hasParent := cm.links[a.SessionID]; !hasParent {
			roots = append(roots, a)
		}
	}

	if len(roots) == 0 {
		return "No agents connected."
	}

	result := "Chain topology:\n  Proxy\n"
	for i, root := range roots {
		isLast := i == len(roots)-1
		result += cm.renderNode(root, agentMap, "  ", isLast)
	}
	return result
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

	result := fmt.Sprintf("%s%s%s %s%s\n", prefix, connector, agent.Name, status, relayInfo)

	// Find children
	var children []AgentInfo
	for child, parent := range cm.links {
		if parent == agent.SessionID {
			if a, ok := agentMap[child]; ok {
				children = append(children, a)
			}
		}
	}

	for i, child := range children {
		isLastChild := i == len(children)-1
		result += cm.renderNode(child, agentMap, childPrefix, isLastChild)
	}

	return result
}
