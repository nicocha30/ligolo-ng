// Ligolo-ng Relay
// Copyright (C) 2025 Nicolas Chatelain (nicocha30)

package app

import (
	"context"
	"sync"
	"time"

	"github.com/allsmog/ligolo-ng-relay/cmd/proxy/config"
	"github.com/sirupsen/logrus"
)

const (
	defaultRelayAutoHealIntervalSeconds  = 30
	defaultRelayAutoHealInterfacePrefix  = "ligolo"
	defaultRelayAutoHealMaxRepairActions = 10
	defaultRelayAutoHealMaxFailovers     = 1
	relayAutoHealModeApply               = "apply"
	relayAutoHealModeMonitor             = "monitor"
)

type RelayAutoHealPolicy struct {
	Enabled          bool   `json:"enabled"`
	Apply            bool   `json:"apply"`
	IntervalSeconds  int64  `json:"interval_seconds"`
	WithIPv6         bool   `json:"with_ipv6"`
	InterfacePrefix  string `json:"interface_prefix"`
	StartTunnels     bool   `json:"start_tunnels"`
	Repair           bool   `json:"repair"`
	PruneConflicts   bool   `json:"prune_conflicts"`
	Failover         bool   `json:"failover"`
	MaxRepairActions int    `json:"max_repair_actions"`
	MaxFailovers     int    `json:"max_failovers"`
}

type RelayAutoHealStatus struct {
	GeneratedAt time.Time           `json:"generated_at"`
	Running     bool                `json:"running"`
	Policy      RelayAutoHealPolicy `json:"policy"`
	LastRun     *RelayAutoHealRun   `json:"last_run,omitempty"`
	NextRunAt   *time.Time          `json:"next_run_at,omitempty"`
}

type RelayAutoHealRun struct {
	StartedAt       time.Time           `json:"started_at"`
	CompletedAt     time.Time           `json:"completed_at"`
	Status          string              `json:"status"`
	Mode            string              `json:"mode"`
	Policy          RelayAutoHealPolicy `json:"policy"`
	Applied         int                 `json:"applied"`
	Failed          int                 `json:"failed"`
	RepairApplied   int                 `json:"repair_applied"`
	RepairFailed    int                 `json:"repair_failed"`
	FailoverApplied int                 `json:"failover_applied"`
	FailoverFailed  int                 `json:"failover_failed"`
	Warnings        []string            `json:"warnings,omitempty"`
	RepairPlan      *ChainRepairPlan    `json:"repair_plan,omitempty"`
	FailoverPlan    *ChainFailoverPlan  `json:"failover_plan,omitempty"`
}

type RelayAutoHealRunRequest struct {
	Apply            *bool
	WithIPv6         *bool
	InterfacePrefix  *string
	StartTunnels     *bool
	Repair           *bool
	PruneConflicts   *bool
	Failover         *bool
	MaxRepairActions *int
	MaxFailovers     *int
}

type relayAutoHealerManager struct {
	mu         sync.Mutex
	policy     RelayAutoHealPolicy
	running    bool
	lastRun    *RelayAutoHealRun
	nextRunAt  *time.Time
	cancel     context.CancelFunc
	generation int64
}

var relayAutoHealer = newRelayAutoHealerManager()

func newRelayAutoHealerManager() *relayAutoHealerManager {
	return &relayAutoHealerManager{
		policy: normalizeRelayAutoHealPolicy(RelayAutoHealPolicy{}),
	}
}

func StartRelayAutoHealFromConfig() {
	relayAutoHealer.Start(relayAutoHealPolicyFromConfig())
}

func RelayAutoHealStatusSnapshot() RelayAutoHealStatus {
	return relayAutoHealer.Status()
}

func RunRelayAutoHealOnce(policy RelayAutoHealPolicy) RelayAutoHealRun {
	return relayAutoHealer.RunOnce(policy)
}

func relayAutoHealPolicyFromConfig() RelayAutoHealPolicy {
	return normalizeRelayAutoHealPolicy(RelayAutoHealPolicy{
		Enabled:          config.Config.GetBool("relay.autoheal.enabled"),
		Apply:            config.Config.GetBool("relay.autoheal.apply"),
		IntervalSeconds:  config.Config.GetInt64("relay.autoheal.interval_seconds"),
		WithIPv6:         config.Config.GetBool("relay.autoheal.with_ipv6"),
		InterfacePrefix:  config.Config.GetString("relay.autoheal.interface_prefix"),
		StartTunnels:     config.Config.GetBool("relay.autoheal.start_tunnels"),
		Repair:           config.Config.GetBool("relay.autoheal.repair"),
		PruneConflicts:   config.Config.GetBool("relay.autoheal.prune_conflicts"),
		Failover:         config.Config.GetBool("relay.autoheal.failover"),
		MaxRepairActions: config.Config.GetInt("relay.autoheal.max_repair_actions"),
		MaxFailovers:     config.Config.GetInt("relay.autoheal.max_failovers"),
	})
}

func relayAutoHealPolicyWithOverrides(policy RelayAutoHealPolicy, req RelayAutoHealRunRequest) RelayAutoHealPolicy {
	if req.Apply != nil {
		policy.Apply = *req.Apply
	}
	if req.WithIPv6 != nil {
		policy.WithIPv6 = *req.WithIPv6
	}
	if req.InterfacePrefix != nil {
		policy.InterfacePrefix = *req.InterfacePrefix
	}
	if req.StartTunnels != nil {
		policy.StartTunnels = *req.StartTunnels
	}
	if req.Repair != nil {
		policy.Repair = *req.Repair
	}
	if req.PruneConflicts != nil {
		policy.PruneConflicts = *req.PruneConflicts
	}
	if req.Failover != nil {
		policy.Failover = *req.Failover
	}
	if req.MaxRepairActions != nil {
		policy.MaxRepairActions = *req.MaxRepairActions
	}
	if req.MaxFailovers != nil {
		policy.MaxFailovers = *req.MaxFailovers
	}
	return normalizeRelayAutoHealPolicy(policy)
}

func normalizeRelayAutoHealPolicy(policy RelayAutoHealPolicy) RelayAutoHealPolicy {
	if policy.IntervalSeconds <= 0 {
		policy.IntervalSeconds = defaultRelayAutoHealIntervalSeconds
	}
	if policy.InterfacePrefix == "" {
		policy.InterfacePrefix = defaultRelayAutoHealInterfacePrefix
	}
	if policy.MaxRepairActions <= 0 {
		policy.MaxRepairActions = defaultRelayAutoHealMaxRepairActions
	}
	if policy.MaxFailovers <= 0 {
		policy.MaxFailovers = defaultRelayAutoHealMaxFailovers
	}
	return policy
}

func (h *relayAutoHealerManager) Start(policy RelayAutoHealPolicy) {
	policy = normalizeRelayAutoHealPolicy(policy)

	h.mu.Lock()
	if h.cancel != nil {
		h.cancel()
		h.cancel = nil
	}
	h.generation++
	generation := h.generation
	h.policy = policy
	h.nextRunAt = nil
	if !policy.Enabled {
		h.mu.Unlock()
		logrus.Debug("Relay auto-heal reconciler disabled")
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel
	nextRunAt := time.Now().Add(time.Duration(policy.IntervalSeconds) * time.Second)
	h.nextRunAt = &nextRunAt
	h.mu.Unlock()

	logrus.Infof("Relay auto-heal reconciler enabled in %s mode, interval %ds", modeForRelayAutoHealPolicy(policy), policy.IntervalSeconds)
	go h.loop(ctx, generation, policy)
}

func (h *relayAutoHealerManager) loop(ctx context.Context, generation int64, policy RelayAutoHealPolicy) {
	interval := time.Duration(policy.IntervalSeconds) * time.Second
	timer := time.NewTimer(interval)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			run := h.RunOnce(policy)
			if run.Status == "error" {
				logrus.Warnf("Relay auto-heal run failed with %d failure(s)", run.Failed)
			} else if run.Applied > 0 {
				logrus.Infof("Relay auto-heal applied %d action(s)", run.Applied)
			}
			nextRunAt := time.Now().Add(interval)
			h.mu.Lock()
			if h.generation == generation {
				h.nextRunAt = &nextRunAt
			}
			h.mu.Unlock()
			timer.Reset(interval)
		}
	}
}

func (h *relayAutoHealerManager) RunOnce(policy RelayAutoHealPolicy) RelayAutoHealRun {
	policy = normalizeRelayAutoHealPolicy(policy)

	h.mu.Lock()
	if h.running {
		h.mu.Unlock()
		now := time.Now()
		return RelayAutoHealRun{
			StartedAt:   now,
			CompletedAt: now,
			Status:      "error",
			Mode:        modeForRelayAutoHealPolicy(policy),
			Policy:      policy,
			Failed:      1,
			Warnings:    []string{"relay auto-heal run already in progress"},
		}
	}
	h.running = true
	h.mu.Unlock()

	run := runRelayAutoHeal(policy)

	h.mu.Lock()
	h.running = false
	h.lastRun = cloneRelayAutoHealRun(&run)
	h.mu.Unlock()
	return run
}

func (h *relayAutoHealerManager) Status() RelayAutoHealStatus {
	h.mu.Lock()
	defer h.mu.Unlock()
	return RelayAutoHealStatus{
		GeneratedAt: time.Now(),
		Running:     h.running,
		Policy:      h.policy,
		LastRun:     cloneRelayAutoHealRun(h.lastRun),
		NextRunAt:   cloneTime(h.nextRunAt),
	}
}

func runRelayAutoHeal(policy RelayAutoHealPolicy) RelayAutoHealRun {
	policy = normalizeRelayAutoHealPolicy(policy)
	run := RelayAutoHealRun{
		StartedAt: time.Now(),
		Status:    "ok",
		Mode:      modeForRelayAutoHealPolicy(policy),
		Policy:    policy,
	}
	if !policy.Repair && !policy.Failover {
		run.Warnings = append(run.Warnings, "relay auto-heal policy has both repair and failover disabled")
	}
	pendingWork := false

	if policy.Repair {
		repairPlan := chainRepairPlan(policy.WithIPv6, policy.InterfacePrefix, policy.StartTunnels, policy.PruneConflicts)
		if policy.Apply {
			repairPlan = applyChainRepairPlanWithLimit(policy.WithIPv6, policy.InterfacePrefix, policy.StartTunnels, policy.PruneConflicts, policy.MaxRepairActions)
		}
		run.RepairPlan = &repairPlan
		run.RepairApplied = repairPlan.Summary.Applied
		run.RepairFailed = repairPlan.Summary.Failed
		run.Applied += repairPlan.Summary.Applied
		run.Failed += repairPlan.Summary.Failed
		if repairPlan.Summary.Actions > repairPlan.Summary.Applied {
			pendingWork = true
			run.Warnings = append(run.Warnings, "repair plan still has pending action(s)")
		}
		if policy.Apply && repairPlan.Summary.ApplySupported > repairPlan.Summary.Applied {
			run.Warnings = append(run.Warnings, "repair apply limit or unsupported actions left work pending")
		}
	}

	if policy.Failover {
		failoverPlan := chainFailoverPlan(false)
		if policy.Apply {
			failoverPlan = applyChainFailoverPlanWithLimit(false, true, nil, nil, policy.MaxFailovers)
		}
		run.FailoverPlan = &failoverPlan
		run.FailoverApplied = failoverPlan.Summary.Applied
		run.FailoverFailed = failoverPlan.Summary.Failed
		run.Applied += failoverPlan.Summary.Applied
		run.Failed += failoverPlan.Summary.Failed
		if failoverPlan.Summary.Recommendations > failoverPlan.Summary.Applied {
			pendingWork = true
			run.Warnings = append(run.Warnings, "failover plan still has pending recommendation(s)")
		}
		if policy.Apply && failoverPlan.Summary.ApplySupported > failoverPlan.Summary.Applied {
			run.Warnings = append(run.Warnings, "failover apply limit or unsupported recommendations left work pending")
		}
	}

	if !policy.Apply && pendingWork {
		run.Warnings = append(run.Warnings, "relay auto-heal is in monitor mode; no changes applied")
	}
	run.CompletedAt = time.Now()
	if run.Failed > 0 {
		run.Status = "error"
	} else if len(run.Warnings) > 0 {
		run.Status = "warning"
	}
	return run
}

func modeForRelayAutoHealPolicy(policy RelayAutoHealPolicy) string {
	if policy.Apply {
		return relayAutoHealModeApply
	}
	return relayAutoHealModeMonitor
}

func cloneRelayAutoHealRun(run *RelayAutoHealRun) *RelayAutoHealRun {
	if run == nil {
		return nil
	}
	cloned := *run
	cloned.Warnings = append([]string(nil), run.Warnings...)
	return &cloned
}

func cloneTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}
