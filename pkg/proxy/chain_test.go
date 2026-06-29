// Ligolo-ng Relay
// Copyright (C) 2025 Nicolas Chatelain (nicocha30)

package proxy

import (
	"testing"
	"time"
)

func TestChainManagerRemoveAgentRemovesDescendants(t *testing.T) {
	cm := NewChainManager()
	cm.AddLink("agent-a", "agent-b")
	cm.AddLink("agent-b", "agent-c")
	cm.AddLink("agent-c", "agent-d")

	cm.RemoveAgent("agent-b")

	if parent := cm.GetParentSessionID("agent-b"); parent != "" {
		t.Fatalf("agent-b parent = %q, want empty", parent)
	}
	if parent := cm.GetParentSessionID("agent-c"); parent != "" {
		t.Fatalf("agent-c parent = %q, want empty", parent)
	}
	if parent := cm.GetParentSessionID("agent-d"); parent != "" {
		t.Fatalf("agent-d parent = %q, want empty", parent)
	}
}

func TestChainManagerDepthLimitAllowsFiveAgentBranch(t *testing.T) {
	cm := NewChainManager()
	cm.AddLink("agent-a", "agent-b")
	cm.AddLink("agent-b", "agent-c")
	cm.AddLink("agent-c", "agent-d")

	if cm.WouldExceedMaxDepth("agent-d") {
		t.Fatal("agent-d should be allowed to relay one more downstream agent")
	}

	cm.AddLink("agent-d", "agent-e")
	if !cm.WouldExceedMaxDepth("agent-e") {
		t.Fatal("agent-e should be the last allowed agent in the branch")
	}
}

func TestChainSnapshotIncludesStructuredTopology(t *testing.T) {
	cm := NewChainManager()
	cm.AddLink("agent-a", "agent-b")
	pathRTTMS := int64(12)
	tokenExpiresAt := time.Now().Add(time.Hour)

	snapshot := cm.Snapshot([]AgentInfo{
		{
			AgentID:              1,
			Name:                 "root@agent-a",
			SessionID:            "agent-a",
			RemoteAddr:           "10.0.0.1:50000",
			RelayActive:          true,
			RelayListenAddr:      "0.0.0.0:11602",
			RelayCertFingerprint: "ABCD",
			RelayTokenExpiresAt:  &tokenExpiresAt,
			RelayOneTimeToken:    true,
			Alive:                true,
			PathRTTMS:            &pathRTTMS,
		},
		{
			AgentID:   2,
			Name:      "root@agent-b",
			SessionID: "agent-b",
			Alive:     true,
		},
	})

	if snapshot.Topology == "" {
		t.Fatal("snapshot topology is empty")
	}
	if snapshot.MaxDepth != MaxChainDepth {
		t.Fatalf("snapshot MaxDepth = %d, want %d", snapshot.MaxDepth, MaxChainDepth)
	}
	if len(snapshot.Agents) != 1 {
		t.Fatalf("root count = %d, want 1", len(snapshot.Agents))
	}
	root := snapshot.Agents[0]
	if root.SessionID != "agent-a" || !root.RelayActive || root.DownstreamCount != 1 {
		t.Fatalf("unexpected root node: %+v", root)
	}
	if root.PathRTTMS == nil || *root.PathRTTMS != pathRTTMS {
		t.Fatalf("root path RTT = %v, want %d", root.PathRTTMS, pathRTTMS)
	}
	if root.RelayCertFingerprint != "ABCD" || root.RelayTokenExpiresAt == nil || !root.RelayOneTimeToken {
		t.Fatalf("root relay metadata missing: %+v", root)
	}
	if len(root.Children) != 1 {
		t.Fatalf("child count = %d, want 1", len(root.Children))
	}
	child := root.Children[0]
	if child.SessionID != "agent-b" || child.ParentSessionID != "agent-a" || child.HopDepth != 1 {
		t.Fatalf("unexpected child node: %+v", child)
	}
}
