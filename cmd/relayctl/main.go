// Ligolo-ng Relay
// Copyright (C) 2025 Nicolas Chatelain (nicocha30)

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/allsmog/ligolo-ng-relay/pkg/relayapi"
)

func main() {
	apiURL := envDefault("LIGOLO_API", "http://127.0.0.1:8080")
	username := envDefault("LIGOLO_USER", "")
	password := envDefault("LIGOLO_PASSWORD", "")
	token := envDefault("LIGOLO_TOKEN", "")

	global := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	global.StringVar(&apiURL, "api", apiURL, "Ligolo-ng Relay API base URL")
	global.StringVar(&username, "user", username, "API username")
	global.StringVar(&password, "password", password, "API password")
	global.StringVar(&token, "token", token, "API bearer token")
	global.Usage = usage
	if err := global.Parse(os.Args[1:]); err != nil {
		fatal(err)
	}
	if global.NArg() == 0 {
		usage()
		os.Exit(2)
	}

	c := relayapi.New(relayapi.Config{
		BaseURL:  apiURL,
		Username: username,
		Password: password,
		Token:    token,
	})

	cmd := global.Arg(0)
	args := global.Args()[1:]
	var err error
	switch cmd {
	case "agents":
		err = printResult(c, "GET", "/api/v1/agents", nil)
	case "chains":
		err = printResult(c, "GET", "/api/v1/chains", nil)
	case "doctor":
		err = runDoctor(c, args)
	case "ops":
		err = runOps(c, args)
	case "chain-routes":
		err = runChainRoutes(c, args)
	case "chain-plan":
		err = runChainPlan(c, args)
	case "chain-repair":
		err = runChainRepair(c, args)
	case "chain-failover":
		err = runChainFailover(c, args)
	case "autoheal":
		err = runAutoHeal(c, args)
	case "chain-autoroute":
		err = runChainAutoroute(c, args)
	case "relay-start":
		err = runRelayStart(c, args)
	case "relay-stop":
		err = runRelayStop(c, args)
	case "relay-token-rotate":
		err = runRelayTokenRotate(c, args)
	case "relay-token-revoke":
		err = runRelayTokenRevoke(c, args)
	default:
		err = fmt.Errorf("unknown command %q", cmd)
	}
	if err != nil {
		fatal(err)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `Usage:
  relayctl [global flags] agents
  relayctl [global flags] chains
  relayctl [global flags] doctor [--with-ipv6] [--interface-prefix ligolo]
  relayctl [global flags] ops [--with-ipv6] [--interface-prefix ligolo] [--fail-on-warning]
  relayctl [global flags] chain-routes [--with-ipv6] [--interface-prefix ligolo]
  relayctl [global flags] chain-plan [--with-ipv6] [--interface-prefix ligolo] [--start]
  relayctl [global flags] chain-repair [--with-ipv6] [--interface-prefix ligolo] [--start] [--prune-conflicts] [--apply]
  relayctl [global flags] chain-failover [--include-commands] [--apply] [--all] [--sessions session-a,session-b] [--agents 2,3]
  relayctl [global flags] autoheal [--run] [--apply] [--with-ipv6] [--interface-prefix ligolo] [--start] [--prune-conflicts] [--repair=false] [--failover=false] [--max-repair-actions 10] [--max-failovers 1]
  relayctl [global flags] chain-autoroute [--with-ipv6] [--interface-prefix ligolo] [--start]
  relayctl [global flags] relay-start --agent id --listen 127.0.0.1:11602 [--relay-token token] [--token-ttl 8h] [--one-time-token]
  relayctl [global flags] relay-stop --agent id
  relayctl [global flags] relay-token-rotate --agent id [--relay-token token] [--token-ttl 8h] [--one-time-token]
  relayctl [global flags] relay-token-revoke --agent id

Global flags:
`)
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	fmt.Fprintln(os.Stderr, "  -api string")
	fmt.Fprintln(os.Stderr, "        Ligolo-ng Relay API base URL (or LIGOLO_API)")
	fmt.Fprintln(os.Stderr, "  -user string")
	fmt.Fprintln(os.Stderr, "        API username (or LIGOLO_USER)")
	fmt.Fprintln(os.Stderr, "  -password string")
	fmt.Fprintln(os.Stderr, "        API password (or LIGOLO_PASSWORD)")
	fmt.Fprintln(os.Stderr, "  -token string")
	fmt.Fprintln(os.Stderr, "        API bearer token (or LIGOLO_TOKEN)")
}

func runDoctor(c *relayapi.Client, args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ExitOnError)
	withIPv6 := fs.Bool("with-ipv6", false, "include IPv6 route candidates")
	interfacePrefix := fs.String("interface-prefix", "ligolo", "interface prefix")
	if err := fs.Parse(args); err != nil {
		return err
	}
	q := url.Values{}
	q.Set("with_ipv6", fmt.Sprintf("%t", *withIPv6))
	q.Set("interface_prefix", *interfacePrefix)
	return printResult(c, "GET", "/api/v1/relay/doctor?"+q.Encode(), nil)
}

func runOps(c *relayapi.Client, args []string) error {
	fs := flag.NewFlagSet("ops", flag.ExitOnError)
	withIPv6 := fs.Bool("with-ipv6", false, "include IPv6 route candidates")
	interfacePrefix := fs.String("interface-prefix", "ligolo", "interface prefix")
	failOnWarning := fs.Bool("fail-on-warning", false, "exit non-zero when relay ops status is not ok")
	if err := fs.Parse(args); err != nil {
		return err
	}
	q := url.Values{}
	q.Set("with_ipv6", fmt.Sprintf("%t", *withIPv6))
	q.Set("interface_prefix", *interfacePrefix)
	payload, err := c.Do(context.Background(), "GET", "/api/v1/relay/ops?"+q.Encode(), nil)
	if err != nil {
		return err
	}
	printPayload(payload)
	if !*failOnWarning {
		return nil
	}
	var status struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(payload, &status); err != nil {
		return err
	}
	if status.Status != "ok" {
		return fmt.Errorf("relay ops status is %q", status.Status)
	}
	return nil
}

func runChainRoutes(c *relayapi.Client, args []string) error {
	fs := flag.NewFlagSet("chain-routes", flag.ExitOnError)
	withIPv6 := fs.Bool("with-ipv6", false, "include IPv6 route candidates")
	interfacePrefix := fs.String("interface-prefix", "ligolo", "interface prefix")
	if err := fs.Parse(args); err != nil {
		return err
	}
	q := url.Values{}
	q.Set("with_ipv6", fmt.Sprintf("%t", *withIPv6))
	q.Set("interface_prefix", *interfacePrefix)
	return printResult(c, "GET", "/api/v1/chain_routes?"+q.Encode(), nil)
}

func runChainPlan(c *relayapi.Client, args []string) error {
	fs := flag.NewFlagSet("chain-plan", flag.ExitOnError)
	withIPv6 := fs.Bool("with-ipv6", false, "include IPv6 route candidates")
	interfacePrefix := fs.String("interface-prefix", "ligolo", "interface prefix")
	start := fs.Bool("start", false, "include tunnel start actions in the dry-run plan")
	if err := fs.Parse(args); err != nil {
		return err
	}
	q := url.Values{}
	q.Set("with_ipv6", fmt.Sprintf("%t", *withIPv6))
	q.Set("interface_prefix", *interfacePrefix)
	q.Set("start", fmt.Sprintf("%t", *start))
	return printResult(c, "GET", "/api/v1/chain_route_plan?"+q.Encode(), nil)
}

func runChainRepair(c *relayapi.Client, args []string) error {
	fs := flag.NewFlagSet("chain-repair", flag.ExitOnError)
	withIPv6 := fs.Bool("with-ipv6", false, "include IPv6 route candidates")
	interfacePrefix := fs.String("interface-prefix", "ligolo", "interface prefix")
	start := fs.Bool("start", false, "include or apply tunnel start actions")
	pruneConflicts := fs.Bool("prune-conflicts", false, "remove configured lower-ranked duplicate routes")
	apply := fs.Bool("apply", false, "apply supported repair actions")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *apply {
		return printResult(c, "POST", "/api/v1/chain_repair", map[string]any{
			"WithIPv6":        *withIPv6,
			"InterfacePrefix": *interfacePrefix,
			"Start":           *start,
			"PruneConflicts":  *pruneConflicts,
		})
	}
	q := url.Values{}
	q.Set("with_ipv6", fmt.Sprintf("%t", *withIPv6))
	q.Set("interface_prefix", *interfacePrefix)
	q.Set("start", fmt.Sprintf("%t", *start))
	q.Set("prune_conflicts", fmt.Sprintf("%t", *pruneConflicts))
	return printResult(c, "GET", "/api/v1/chain_repair_plan?"+q.Encode(), nil)
}

func runChainFailover(c *relayapi.Client, args []string) error {
	fs := flag.NewFlagSet("chain-failover", flag.ExitOnError)
	includeCommands := fs.Bool("include-commands", false, "include downstream reconnect commands with relay tokens")
	apply := fs.Bool("apply", false, "apply selected failover recommendations")
	all := fs.Bool("all", false, "apply every supported failover recommendation")
	sessions := fs.String("sessions", "", "comma-separated SessionIDs to fail over")
	agents := fs.String("agents", "", "comma-separated agent IDs to fail over")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *apply {
		sessionIDs := parseCSVStrings(*sessions)
		agentIDs, err := parseCSVInts(*agents)
		if err != nil {
			return err
		}
		if !*all && len(sessionIDs) == 0 && len(agentIDs) == 0 {
			return errors.New("chain-failover --apply requires --all, --sessions, or --agents")
		}
		return printResult(c, "POST", "/api/v1/chain_failover", map[string]any{
			"IncludeCommands": *includeCommands,
			"All":             *all,
			"SessionIDs":      sessionIDs,
			"AgentIDs":        agentIDs,
		})
	}
	q := url.Values{}
	q.Set("include_commands", fmt.Sprintf("%t", *includeCommands))
	return printResult(c, "GET", "/api/v1/chain_failover_plan?"+q.Encode(), nil)
}

func parseCSVStrings(value string) []string {
	var values []string
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		if item != "" {
			values = append(values, item)
		}
	}
	return values
}

func parseCSVInts(value string) ([]int, error) {
	var values []int
	for _, item := range parseCSVStrings(value) {
		parsed, err := strconv.Atoi(item)
		if err != nil {
			return nil, fmt.Errorf("invalid integer %q", item)
		}
		values = append(values, parsed)
	}
	return values, nil
}

func runAutoHeal(c *relayapi.Client, args []string) error {
	fs := flag.NewFlagSet("autoheal", flag.ExitOnError)
	run := fs.Bool("run", false, "run one relay auto-heal reconciliation")
	apply := fs.Bool("apply", false, "apply supported repair and failover actions")
	withIPv6 := fs.Bool("with-ipv6", false, "include IPv6 route candidates")
	interfacePrefix := fs.String("interface-prefix", "ligolo", "interface prefix")
	start := fs.Bool("start", false, "include or apply tunnel start repair actions")
	pruneConflicts := fs.Bool("prune-conflicts", false, "remove configured lower-ranked duplicate routes")
	repair := fs.Bool("repair", true, "include repair actions")
	failover := fs.Bool("failover", true, "include failover recommendations")
	maxRepairActions := fs.Int("max-repair-actions", 10, "maximum repair actions to attempt per run")
	maxFailovers := fs.Int("max-failovers", 1, "maximum failover recommendations to attempt per run")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if !*run {
		return printResult(c, "GET", "/api/v1/relay/autoheal", nil)
	}
	return printResult(c, "POST", "/api/v1/relay/autoheal/run", map[string]any{
		"Apply":            *apply,
		"WithIPv6":         *withIPv6,
		"InterfacePrefix":  *interfacePrefix,
		"StartTunnels":     *start,
		"Repair":           *repair,
		"PruneConflicts":   *pruneConflicts,
		"Failover":         *failover,
		"MaxRepairActions": *maxRepairActions,
		"MaxFailovers":     *maxFailovers,
	})
}

func runChainAutoroute(c *relayapi.Client, args []string) error {
	fs := flag.NewFlagSet("chain-autoroute", flag.ExitOnError)
	withIPv6 := fs.Bool("with-ipv6", false, "include IPv6 route candidates")
	interfacePrefix := fs.String("interface-prefix", "ligolo", "interface prefix")
	start := fs.Bool("start", false, "start tunnels after configuring routes")
	if err := fs.Parse(args); err != nil {
		return err
	}
	return printResult(c, "POST", "/api/v1/chain_autoroute", map[string]any{
		"WithIPv6":        *withIPv6,
		"InterfacePrefix": *interfacePrefix,
		"Start":           *start,
	})
}

func runRelayStart(c *relayapi.Client, args []string) error {
	fs := flag.NewFlagSet("relay-start", flag.ExitOnError)
	agentID := fs.Int("agent", 0, "agent ID")
	listenAddr := fs.String("listen", "127.0.0.1:11602", "relay listen address")
	relayToken := fs.String("relay-token", os.Getenv("LIGOLO_RELAY_TOKEN"), "relay auth token (or LIGOLO_RELAY_TOKEN); generated when empty")
	tokenTTL := fs.String("token-ttl", "8h", "relay auth token lifetime")
	oneTimeToken := fs.Bool("one-time-token", false, "allow the token to authenticate one downstream agent only")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *agentID <= 0 {
		return errors.New("relay-start requires --agent")
	}
	tokenTTLSeconds, err := parseTokenTTLSeconds(*tokenTTL)
	if err != nil {
		return err
	}
	return printResult(c, "POST", fmt.Sprintf("/api/v1/relay/%d", *agentID), map[string]any{
		"ListenAddr":      *listenAddr,
		"AuthToken":       *relayToken,
		"TokenTTLSeconds": tokenTTLSeconds,
		"OneTimeToken":    *oneTimeToken,
	})
}

func runRelayStop(c *relayapi.Client, args []string) error {
	fs := flag.NewFlagSet("relay-stop", flag.ExitOnError)
	agentID := fs.Int("agent", 0, "agent ID")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *agentID <= 0 {
		return errors.New("relay-stop requires --agent")
	}
	return printResult(c, "DELETE", fmt.Sprintf("/api/v1/relay/%d", *agentID), nil)
}

func runRelayTokenRotate(c *relayapi.Client, args []string) error {
	fs := flag.NewFlagSet("relay-token-rotate", flag.ExitOnError)
	agentID := fs.Int("agent", 0, "agent ID")
	relayToken := fs.String("relay-token", os.Getenv("LIGOLO_RELAY_TOKEN"), "new relay auth token (or LIGOLO_RELAY_TOKEN); generated when empty")
	tokenTTL := fs.String("token-ttl", "8h", "relay auth token lifetime")
	oneTimeToken := fs.Bool("one-time-token", false, "allow the token to authenticate one downstream agent only")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *agentID <= 0 {
		return errors.New("relay-token-rotate requires --agent")
	}
	tokenTTLSeconds, err := parseTokenTTLSeconds(*tokenTTL)
	if err != nil {
		return err
	}
	return printResult(c, "POST", fmt.Sprintf("/api/v1/relay/%d/token", *agentID), map[string]any{
		"AuthToken":       *relayToken,
		"TokenTTLSeconds": tokenTTLSeconds,
		"OneTimeToken":    *oneTimeToken,
	})
}

func runRelayTokenRevoke(c *relayapi.Client, args []string) error {
	fs := flag.NewFlagSet("relay-token-revoke", flag.ExitOnError)
	agentID := fs.Int("agent", 0, "agent ID")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *agentID <= 0 {
		return errors.New("relay-token-revoke requires --agent")
	}
	return printResult(c, "DELETE", fmt.Sprintf("/api/v1/relay/%d/token", *agentID), nil)
}

func parseTokenTTLSeconds(value string) (int64, error) {
	duration, err := time.ParseDuration(value)
	if err != nil || duration <= 0 {
		return 0, fmt.Errorf("invalid token TTL %q", value)
	}
	return int64(duration.Seconds()), nil
}

func printResult(c *relayapi.Client, method, path string, body any) error {
	payload, err := c.Do(context.Background(), method, path, body)
	if err != nil {
		return err
	}
	printPayload(payload)
	return nil
}

func printPayload(payload []byte) {
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, payload, "", "  "); err != nil {
		fmt.Println(string(payload))
		return
	}
	fmt.Println(pretty.String())
}

func envDefault(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "relayctl:", err)
	os.Exit(1)
}
