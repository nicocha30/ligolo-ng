#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DOCKER_BIN="${DOCKER:-docker}"
API_PORT="${RELAY_TEST_API_PORT:-18080}"
IDLE_SECONDS="${RELAY_TEST_IDLE_SECONDS:-5}"
IMAGE="ligolo-ng-relay-test:$(date +%s)"
NET="ligolo-relay-net-$$"
PROXY="ligolo-test-proxy-$$"
AGENTA="ligolo-test-agent-a-$$"
AGENTB="ligolo-test-agent-b-$$"
AGENTC="ligolo-test-agent-c-$$"
TMP_DIR="$(mktemp -d "$ROOT/.relay-test.XXXXXX")"
DOCKER_READY=0
HTTP_PORT=18082
LISTENER_PORT=18081
HTTP_PAYLOAD="ligolo-depth3-$$"

docker_cmd() {
	$DOCKER_BIN "$@"
}

cleanup() {
	status=$?
	if [ "$DOCKER_READY" -eq 1 ] && [ "$status" -ne 0 ]; then
		echo "--- proxy logs ---" >&2
		docker_cmd logs "$PROXY" >&2 || true
		echo "--- agent-a logs ---" >&2
		docker_cmd logs "$AGENTA" >&2 || true
		echo "--- agent-b logs ---" >&2
		docker_cmd logs "$AGENTB" >&2 || true
		echo "--- agent-c logs ---" >&2
		docker_cmd logs "$AGENTC" >&2 || true
	fi
	if [ "$DOCKER_READY" -eq 1 ]; then
		docker_cmd rm -f "$AGENTC" "$AGENTB" "$AGENTA" "$PROXY" >/dev/null 2>&1 || true
		docker_cmd network rm "$NET" >/dev/null 2>&1 || true
		docker_cmd rmi "$IMAGE" >/dev/null 2>&1 || true
	fi
	rm -rf "$TMP_DIR"
}
trap cleanup EXIT

require() {
	if ! command -v "$1" >/dev/null 2>&1; then
		echo "missing required command: $1" >&2
		exit 1
	fi
}

require curl
require jq

if ! docker_cmd version >/dev/null 2>&1; then
	echo "docker is not reachable; set DOCKER='sudo docker' if needed or start the Docker daemon" >&2
	exit 1
fi
DOCKER_READY=1

if ss -ltn "sport = :$API_PORT" 2>/dev/null | grep -q LISTEN; then
	echo "api port $API_PORT is already in use" >&2
	exit 1
fi

printf '{}\n' > "$TMP_DIR/ligolo-ng-relay.yaml"

api_get() {
	curl -fsS "http://127.0.0.1:$API_PORT/api/v1/$1" -H "Authorization: $TOKEN"
}

api_post() {
	curl -fsS "http://127.0.0.1:$API_PORT/api/v1/$1" \
		-H "Authorization: $TOKEN" -H 'Content-Type: application/json' \
		-d "$2"
}

api_delete() {
	curl -fsS -X DELETE "http://127.0.0.1:$API_PORT/api/v1/$1" -H "Authorization: $TOKEN"
}

wait_for_agent() {
	session_id="$1"
	for i in $(seq 1 80); do
		AGENTS="$(api_get agents || true)"
		agent_id="$(echo "$AGENTS" | jq -r --arg sid "$session_id" 'to_entries[] | select(.value.SessionID == $sid and .value.RelayCapable == true) | .key' 2>/dev/null || true)"
		if [ -n "$agent_id" ]; then
			printf '%s\n' "$agent_id"
			return 0
		fi
		sleep 0.5
	done
	echo "agent $session_id did not register" >&2
	echo "$AGENTS" >&2
	return 1
}

start_relay() {
	agent_id="$1"
	listen_addr="$2"
	out_prefix="$3"
	relay_resp="$(api_post "relay/$agent_id" "{\"ListenAddr\":\"$listen_addr\"}")"
	echo "$relay_resp" | jq -e '.message == "relay started" and (.fingerprint | length > 0) and (.auth_token | length > 0) and (.connect_command | contains("-accept-fingerprint")) and (.connect_command | contains("-relay-token"))' >/dev/null
	printf -v "${out_prefix}_FINGERPRINT" '%s' "$(echo "$relay_resp" | jq -r '.fingerprint')"
	printf -v "${out_prefix}_AUTH_TOKEN" '%s' "$(echo "$relay_resp" | jq -r '.auth_token')"
}

start_downstream_agent() {
	container_name="$1"
	session_id="$2"
	connect_addr="$3"
	fingerprint="$4"
	auth_token="$5"
	docker_cmd run -d --name "$container_name" --network "$NET" -e LIGOLO_SESSION_ID="$session_id" "$IMAGE" \
		ligolo-agent -connect "$connect_addr" -accept-fingerprint "$fingerprint" -relay-token "$auth_token" -reconnect=true -reconnect-delay 1 -reconnect-timeout 30 >/dev/null
}

wait_chain() {
	description="$1"
	jq_expr="$2"
	for i in $(seq 1 100); do
		CHAINS="$(api_get chains || true)"
		if echo "$CHAINS" | jq -e "$jq_expr" >/dev/null 2>&1; then
			return 0
		fi
		sleep 0.5
	done
	echo "$description" >&2
	echo "$CHAINS" >&2
	return 1
}

start_proxy_http() {
	docker_cmd exec "$PROXY" sh -c "mkdir -p /tmp/www && printf '%s\n' '$HTTP_PAYLOAD' > /tmp/www/index.html"
	docker_cmd exec -d "$PROXY" /bin/busybox httpd -f -p "127.0.0.1:$HTTP_PORT" -h /tmp/www
	for i in $(seq 1 30); do
		body="$(docker_cmd exec "$PROXY" /bin/busybox timeout 2 /bin/busybox wget -qO- "http://127.0.0.1:$HTTP_PORT/" 2>/dev/null || true)"
		body="$(printf '%s' "$body" | tr -d '\r\n')"
		if [ "$body" = "$HTTP_PAYLOAD" ]; then
			return 0
		fi
		sleep 0.5
	done
	echo "proxy-side HTTP fixture did not become ready" >&2
	return 1
}

create_agent_c_listener() {
	listener_resp="$(api_post listeners "{\"AgentID\":$AGENT_C_ID,\"ListenerAddr\":\"0.0.0.0:$LISTENER_PORT\",\"RedirectAddr\":\"127.0.0.1:$HTTP_PORT\",\"Network\":\"tcp\"}")"
	echo "$listener_resp" | jq -e '.message == "listener created"' >/dev/null
}

verify_agent_c_listener() {
	description="$1"
	for i in $(seq 1 50); do
		body="$(docker_cmd exec "$AGENTC" /bin/busybox timeout 2 /bin/busybox wget -qO- "http://127.0.0.1:$LISTENER_PORT/" 2>/dev/null || true)"
		body="$(printf '%s' "$body" | tr -d '\r\n')"
		if [ "$body" = "$HTTP_PAYLOAD" ]; then
			return 0
		fi
		sleep 0.5
	done
	echo "$description" >&2
	return 1
}

assert_chain_routes() {
	routes="$(api_get 'chain_routes?with_ipv6=false&interface_prefix=ligolo')"
	echo "$routes" | jq -e '.routes[] | select(.session_id == "agent-c" and .hop_depth == 2 and (.route | type == "string"))' >/dev/null

	plan="$(api_get 'chain_route_plan?with_ipv6=false&interface_prefix=relaytest&start=false')"
	echo "$plan" | jq -e '.summary.apply >= 1 and .summary.skipped >= 1' >/dev/null
	echo "$plan" | jq -e '.decisions[] | select(.session_id == "agent-c" and .hop_depth == 2 and .decision == "skip_conflict" and (.reason | contains("preferred route cost")))' >/dev/null

	repair_plan="$(api_get 'chain_repair_plan?with_ipv6=false&interface_prefix=relaytest&start=false&prune_conflicts=false')"
	echo "$repair_plan" | jq -e '(.summary.apply_supported >= 1) and ([.actions[] | select(.type == "ensure_route" and .apply_supported == true)] | length >= 1)' >/dev/null

	repair="$(api_post chain_repair '{"InterfacePrefix":"relaytest","WithIPv6":false,"Start":false,"PruneConflicts":false}')"
	echo "$repair" | jq -e '(.summary.applied >= 1) and ([.actions[] | select(.type == "ensure_route" and .applied == true)] | length >= 1)' >/dev/null

	failover="$(api_get 'chain_failover_plan?include_commands=true')"
	echo "$failover" | jq -e '(.summary.recommendations >= 1) and ([.recommendations[] | select(.session_id == "agent-c" and .recommended_parent.session_id == "agent-a" and .command_available == true and (.connect_command | contains("-relay-token")))] | length >= 1)' >/dev/null

	autoroute="$(api_post chain_autoroute '{"InterfacePrefix":"relaytest","WithIPv6":false,"Start":false}')"
	echo "$autoroute" | jq -e '.routes[] | select(.session_id == "agent-a" and .hop_depth == 0 and (.interface | startswith("relaytest")))' >/dev/null
	echo "$autoroute" | jq -e '.plan.decisions[] | select(.session_id == "agent-c" and .decision == "skip_conflict")' >/dev/null
}

assert_agent_c_chain() {
	wait_chain "agent C did not register through nested relay" '
		.agents[]
		| select(.session_id == "agent-a" and .relay_active == true and (.path_rtt_ms | type == "number"))
		| .children[]?
		| select(.session_id == "agent-b" and .parent_session_id == "agent-a" and .hop_depth == 1 and .relay_active == true and (.path_rtt_ms | type == "number"))
		| .children[]?
		| select(.session_id == "agent-c" and .parent_session_id == "agent-b" and .hop_depth == 2 and (.path_rtt_ms | type == "number"))
	'
}

assert_agent_c_failed_over_to_a() {
	wait_chain "agent C did not fail over to agent A" '
		.agents[]
		| select(.session_id == "agent-a" and .relay_active == true and (.path_rtt_ms | type == "number"))
		| .children[]?
		| select(.session_id == "agent-c" and .parent_session_id == "agent-a" and .hop_depth == 1 and (.path_rtt_ms | type == "number"))
	'
}

echo "== docker build =="
docker_cmd build -t "$IMAGE" -f "$ROOT/test/relay/Dockerfile" "$ROOT"

echo "== docker network =="
docker_cmd network create "$NET" >/dev/null

echo "== start proxy =="
docker_cmd run -d --name "$PROXY" --network "$NET" --network-alias proxy \
	-p "127.0.0.1:$API_PORT:8080" \
	-v "$TMP_DIR/ligolo-ng-relay.yaml:/work/ligolo-ng-relay.yaml" \
	"$IMAGE" \
	ligolo-proxy -daemon -selfcert -api -no-web-ui \
	-api-laddr 0.0.0.0:8080 \
	-web-user relay -web-password relay-pass \
	-laddr 0.0.0.0:11601 -config ligolo-ng-relay.yaml -nobanner >/dev/null

for i in $(seq 1 60); do
	if curl -fsS "http://127.0.0.1:$API_PORT/api/auth" \
		-H 'Content-Type: application/json' \
		-d '{"Username":"relay","Password":"relay-pass"}' > "$TMP_DIR/token.json" 2>/dev/null; then
		break
	fi
	sleep 0.5
	if [ "$i" -eq 60 ]; then
		echo "proxy API did not become ready" >&2
		exit 1
	fi
done
TOKEN="$(jq -r '.token' "$TMP_DIR/token.json")"

echo "== start agent A direct to proxy =="
docker_cmd run -d --name "$AGENTA" --network "$NET" -e LIGOLO_SESSION_ID=agent-a "$IMAGE" \
	ligolo-agent -connect proxy:11601 -ignore-cert -reconnect=false >/dev/null
AGENT_A_ID="$(wait_for_agent agent-a)"

echo "== start relay on agent A =="
start_relay "$AGENT_A_ID" "0.0.0.0:11602" RELAY_A

echo "== start agent B through relay =="
start_downstream_agent "$AGENTB" agent-b "$AGENTA:11602" "$RELAY_A_FINGERPRINT" "$RELAY_A_AUTH_TOKEN"
AGENT_B_ID="$(wait_for_agent agent-b)"
wait_chain "agent B did not register through relay" '
	.agents[]
	| select(.session_id == "agent-a" and .relay_active == true and (.path_rtt_ms | type == "number"))
	| .children[]?
	| select(.session_id == "agent-b" and .parent_session_id == "agent-a" and .hop_depth == 1 and (.path_rtt_ms | type == "number"))
'

echo "== start relay on agent B =="
start_relay "$AGENT_B_ID" "0.0.0.0:11603" RELAY_B

echo "== start agent C through nested relay =="
start_downstream_agent "$AGENTC" agent-c "$AGENTB:11603" "$RELAY_B_FINGERPRINT" "$RELAY_B_AUTH_TOKEN"
AGENT_C_ID="$(wait_for_agent agent-c)"
assert_agent_c_chain

echo "== verified 3-hop chain =="
echo "$CHAINS" | jq '{topology, agents}'

echo "== verify chain route automation sees agent C =="
assert_chain_routes

echo "== verify listener data plane through agent C =="
start_proxy_http
create_agent_c_listener
verify_agent_c_listener "agent C listener did not relay to proxy HTTP fixture"

echo "== idle relay chain and verify listener again =="
sleep "$IDLE_SECONDS"
verify_agent_c_listener "agent C listener failed after idle period"

echo "== stop relay on agent B and verify descendant cleanup =="
api_delete "relay/$AGENT_B_ID" | jq -e '.message == "relay stopped"' >/dev/null
wait_chain "agent C remained live after relay B stopped" '
	(any(.agents[] | recurse(.children[]?); .session_id == "agent-b" and .relay_active == false))
	and ([.agents[] | recurse(.children[]?) | select(.session_id == "agent-c" and .alive == true)] | length == 0)
'
docker_cmd rm -f "$AGENTC" >/dev/null 2>&1 || true

echo "== restart relay on agent B and re-form agent C =="
start_relay "$AGENT_B_ID" "0.0.0.0:11603" RELAY_B
start_downstream_agent "$AGENTC" agent-c "$AGENTB:11603" "$RELAY_B_FINGERPRINT" "$RELAY_B_AUTH_TOKEN"
AGENT_C_ID="$(wait_for_agent agent-c)"
assert_agent_c_chain
verify_agent_c_listener "restored agent C listener did not relay after reconnect"

echo "== preview auto-heal failover for agent C to agent A =="
autoheal_monitor="$(api_post relay/autoheal/run '{"Apply":false,"Repair":false,"Failover":true,"MaxFailovers":1}')"
echo "$autoheal_monitor" | jq -e '(.mode == "monitor") and (.applied == 0) and (.failover_plan.summary.recommendations >= 1) and ([.failover_plan.recommendations[] | select(.session_id == "agent-c" and .recommended_parent.session_id == "agent-a" and .apply_supported == true)] | length == 1)' >/dev/null

echo "== apply auto-heal failover for agent C to agent A =="
autoheal_apply="$(api_post relay/autoheal/run '{"Apply":true,"Repair":false,"Failover":true,"MaxFailovers":1}')"
echo "$autoheal_apply" | jq -e '(.mode == "apply") and (.failover_applied == 1) and (.failed == 0) and ([.failover_plan.recommendations[] | select(.session_id == "agent-c" and .recommended_parent.session_id == "agent-a" and .applied == true and .apply_supported == true)] | length == 1)' >/dev/null
assert_agent_c_failed_over_to_a
verify_agent_c_listener "failed-over agent C listener did not relay after reconnect"

echo "== kill middle agent B and verify agent C stays on failover path =="
docker_cmd rm -f "$AGENTB" >/dev/null
wait_chain "agent C did not remain live after agent B was killed" '
	([.agents[] | recurse(.children[]?) | select(.session_id == "agent-b" and .alive == true)] | length == 0)
	and
	(any(.agents[] | recurse(.children[]?); .session_id == "agent-c" and .parent_session_id == "agent-a" and .alive == true))
'

echo "== verify relayctl client =="
docker_cmd run --rm --network "$NET" "$IMAGE" \
	relayctl -api http://proxy:8080 -user relay -password relay-pass chains |
	jq -e '([.agents[] | recurse(.children[]?) | select(.session_id == "agent-b" and .alive == true)] | length == 0) and (any(.agents[] | recurse(.children[]?); .session_id == "agent-c" and .parent_session_id == "agent-a" and .alive == true))' >/dev/null

echo "== verify relayctl doctor =="
docker_cmd run --rm --network "$NET" "$IMAGE" \
	relayctl -api http://proxy:8080 -user relay -password relay-pass doctor |
	jq -e '.status == "ok" or .status == "warning"' >/dev/null
echo "PASS relay integration"
