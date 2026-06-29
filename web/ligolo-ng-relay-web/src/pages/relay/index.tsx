import { useCallback, useContext, useMemo, useState } from "react";
import type { ReactNode } from "react";
import {
  Button,
  Card,
  CardBody,
  Checkbox,
  Chip,
  CircularProgress,
  Form,
  Input,
  Modal,
  ModalBody,
  ModalContent,
  ModalFooter,
  ModalHeader,
  Select,
  SelectItem,
  Table,
  TableBody,
  TableCell,
  TableColumn,
  TableHeader,
  TableRow,
  Tooltip,
  useDisclosure,
} from "@heroui/react";
import {
  Activity,
  AlertTriangle,
  Ban,
  CheckCircle2,
  GitBranch,
  KeyRound,
  ListChecks,
  Network,
  Play,
  RefreshCw,
  RotateCcw,
  Route,
  ShieldCheck,
  Users,
  Wrench,
} from "lucide-react";
import ErrorContext from "@/contexts/Error.tsx";
import { handleApiResponse } from "@/hooks/toast.ts";
import useAgents from "@/hooks/useAgents.ts";
import { useApi } from "@/hooks/useApi.ts";
import useRelayOps from "@/hooks/useRelayOps.ts";
import { LigoloAgent, LigoloAgentList } from "@/types/agents.ts";
import {
  ChainFailoverRecommendation,
  ChainNode,
  ChainRepairAction,
  ChainRouteDecision,
  ChainRouteInfo,
  RelayDoctorRelay,
  RelayMeshHealth,
  RelayOpsAction,
} from "@/types/relay.ts";

type ChipColor = "default" | "primary" | "success" | "warning" | "danger";

interface MetricCardProps {
  icon: ReactNode;
  label: string;
  value: number;
  tone: ChipColor;
}

interface RelayStartModalProps {
  agents?: LigoloAgentList;
  isOpen?: boolean;
  mutate?: () => Promise<unknown>;
  mutateAgents?: () => Promise<unknown>;
  onOpenChange?: () => void;
}

function formatDate(value?: string) {
  if (!value) return "-";
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return value;
  return parsed.toLocaleString();
}

function shortFingerprint(value?: string) {
  if (!value) return "-";
  if (value.length <= 18) return value;
  return `${value.slice(0, 10)}...${value.slice(-6)}`;
}

function statusColor(status: string): ChipColor {
  if (status === "ok") return "success";
  if (status === "warning") return "warning";
  return "danger";
}

function severityColor(severity: string): ChipColor {
  if (severity === "critical") return "danger";
  if (severity === "warning") return "warning";
  return "primary";
}

function decisionColor(decision: string): ChipColor {
  if (decision === "apply") return "success";
  if (decision === "skip_conflict") return "warning";
  return "default";
}

function meshStateColor(state: string): ChipColor {
  if (state === "healthy") return "success";
  if (state === "offline") return "danger";
  if (state === "degraded") return "warning";
  return "default";
}

function MetricCard({ icon, label, value, tone }: MetricCardProps) {
  return (
    <Card className="rounded-lg border border-default-200" shadow="none">
      <CardBody className="flex-row items-center gap-3 px-4 py-3">
        <Chip color={tone} size="sm" variant="flat">
          {icon}
        </Chip>
        <div className="min-w-0">
          <p className="text-xl font-semibold leading-7">{value}</p>
          <p className="text-xs uppercase text-default-500">{label}</p>
        </div>
      </CardBody>
    </Card>
  );
}

function ChainNodeRow({ node }: { node: ChainNode }) {
  const children = node.children ?? [];
  return (
    <li className="flex flex-col gap-2">
      <div className="rounded-lg border border-default-200 px-4 py-3">
        <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <p className="truncate text-sm font-semibold">{node.name}</p>
              <Chip color={node.alive ? "success" : "danger"} size="sm" variant="flat">
                {node.state}
              </Chip>
              {node.relay_active ? (
                <Chip color="primary" size="sm" variant="flat">
                  Relay
                </Chip>
              ) : null}
              {node.tunnel_running ? (
                <Chip color="success" size="sm" variant="flat">
                  Tunnel
                </Chip>
              ) : null}
            </div>
            <p className="mt-1 break-all text-xs text-default-500">
              {node.session_id}
            </p>
          </div>
          <div className="grid grid-cols-2 gap-2 text-xs text-default-500 sm:grid-cols-4">
            <span>Hop {node.hop_depth}</span>
            <span>{node.path_rtt_ms ?? "-"} ms</span>
            <span>{node.downstream_count} downstream</span>
            <span>{node.remote_addr || "-"}</span>
          </div>
        </div>
      </div>
      {children.length > 0 ? (
        <ul className="ml-4 flex flex-col gap-2 border-l border-default-200 pl-4">
          {children.map((child) => (
            <ChainNodeRow key={child.session_id} node={child} />
          ))}
        </ul>
      ) : null}
    </li>
  );
}

function ActionCard({ action }: { action: RelayOpsAction }) {
  return (
    <Card className="rounded-lg border border-default-200" shadow="none">
      <CardBody className="gap-2 px-4 py-3">
        <div className="flex items-center justify-between gap-3">
          <p className="text-sm font-semibold">{action.title}</p>
          <Chip color={severityColor(action.severity)} size="sm" variant="flat">
            {action.severity}
          </Chip>
        </div>
        {action.detail ? (
          <p className="text-sm text-default-500">{action.detail}</p>
        ) : null}
        {action.agent_id ? (
          <p className="text-xs text-default-400">Agent {action.agent_id}</p>
        ) : null}
      </CardBody>
    </Card>
  );
}

function RelayEventLine({ relay }: { relay: RelayDoctorRelay }) {
  const events = relay.relay.recent_events ?? [];
  const lastEvent = events.length > 0 ? events[events.length - 1] : undefined;
  if (!lastEvent) return <span className="text-default-400">-</span>;
  return (
    <div className="max-w-[280px]">
      <p className="truncate text-sm">{lastEvent.kind}</p>
      <p className="truncate text-xs text-default-500">{lastEvent.message}</p>
    </div>
  );
}

function RelayControlsTable({
  relays,
  onRotateToken,
  onRevokeToken,
}: {
  relays: RelayDoctorRelay[];
  onRotateToken: (agentID: number) => () => Promise<void>;
  onRevokeToken: (agentID: number) => () => Promise<void>;
}) {
  return (
    <Table aria-label="Relay controls">
      <TableHeader>
        <TableColumn className="uppercase">Agent</TableColumn>
        <TableColumn className="uppercase">Relay</TableColumn>
        <TableColumn className="uppercase">Token</TableColumn>
        <TableColumn className="uppercase">Problems</TableColumn>
        <TableColumn className="uppercase">Recent Event</TableColumn>
        <TableColumn className="uppercase">Actions</TableColumn>
      </TableHeader>
      <TableBody emptyContent={"No relay activity."}>
        <>
          {relays.map((relay) => (
            <TableRow key={relay.agent_id}>
              <TableCell>
                <div className="flex flex-col">
                  <p className="text-sm font-semibold">{relay.name}</p>
                  <p className="text-xs text-default-500">
                    #{relay.agent_id} - {relay.session_id}
                  </p>
                </div>
              </TableCell>
              <TableCell>
                <div className="flex flex-col gap-1">
                  <Chip
                    color={relay.relay.active ? "success" : "default"}
                    size="sm"
                    variant="flat"
                  >
                    {relay.relay.active ? "Active" : "Inactive"}
                  </Chip>
                  <span className="text-xs text-default-500">
                    {relay.relay.listen_addr || "-"}
                  </span>
                  <span className="text-xs text-default-400">
                    {shortFingerprint(relay.relay.fingerprint)}
                  </span>
                </div>
              </TableCell>
              <TableCell>
                <div className="flex flex-col gap-1">
                  <Chip
                    color={relay.relay.token_expired ? "danger" : "success"}
                    size="sm"
                    variant="flat"
                  >
                    {relay.relay.token_expired ? "Expired" : "Valid"}
                  </Chip>
                  <span className="text-xs text-default-500">
                    {formatDate(relay.relay.token_expires_at)}
                  </span>
                  {relay.relay.one_time_token ? (
                    <span className="text-xs text-default-400">One-time token</span>
                  ) : null}
                </div>
              </TableCell>
              <TableCell>
                <div className="flex max-w-[260px] flex-wrap gap-1">
                  {(relay.problems ?? []).length > 0 ? (
                    relay.problems?.map((problem) => (
                      <Chip key={problem} color="warning" size="sm" variant="flat">
                        {problem}
                      </Chip>
                    ))
                  ) : (
                    <span className="text-default-400">-</span>
                  )}
                </div>
              </TableCell>
              <TableCell>
                <RelayEventLine relay={relay} />
              </TableCell>
              <TableCell>
                <div className="flex items-center gap-2">
                  <Tooltip content="Rotate token">
                    <Button
                      color="primary"
                      isDisabled={!relay.relay.active}
                      isIconOnly
                      size="sm"
                      variant="flat"
                      onPress={onRotateToken(relay.agent_id)}
                    >
                      <KeyRound size={18} />
                    </Button>
                  </Tooltip>
                  <Tooltip color="danger" content="Revoke token">
                    <Button
                      color="danger"
                      isDisabled={!relay.relay.active}
                      isIconOnly
                      size="sm"
                      variant="flat"
                      onPress={onRevokeToken(relay.agent_id)}
                    >
                      <Ban size={18} />
                    </Button>
                  </Tooltip>
                </div>
              </TableCell>
            </TableRow>
          ))}
        </>
      </TableBody>
    </Table>
  );
}

function RouteConflictTable({ routes }: { routes: ChainRouteInfo[] }) {
  return (
    <Table aria-label="Route conflicts">
      <TableHeader>
        <TableColumn className="uppercase">Agent</TableColumn>
        <TableColumn className="uppercase">Interface</TableColumn>
        <TableColumn className="uppercase">Route</TableColumn>
        <TableColumn className="uppercase">Conflict With</TableColumn>
        <TableColumn className="uppercase">Warning</TableColumn>
      </TableHeader>
      <TableBody emptyContent={"No route conflicts."}>
        <>
          {routes.map((route) => (
            <TableRow key={`${route.agent_id}-${route.route}`}>
              <TableCell>
                <div className="flex flex-col">
                  <p className="text-sm font-semibold">{route.name}</p>
                  <p className="text-xs text-default-500">#{route.agent_id}</p>
                </div>
              </TableCell>
              <TableCell>{route.interface}</TableCell>
              <TableCell>{route.route}</TableCell>
              <TableCell>{route.conflict_with?.join(", ") || "-"}</TableCell>
              <TableCell>{route.warning || "-"}</TableCell>
            </TableRow>
          ))}
        </>
      </TableBody>
    </Table>
  );
}

function MeshHealthTable({ health }: { health: RelayMeshHealth[] }) {
  return (
    <Table aria-label="Relay mesh health">
      <TableHeader>
        <TableColumn className="uppercase">Agent</TableColumn>
        <TableColumn className="uppercase">State</TableColumn>
        <TableColumn className="uppercase">Path</TableColumn>
        <TableColumn className="uppercase">Issues</TableColumn>
        <TableColumn className="uppercase">Recovery</TableColumn>
      </TableHeader>
      <TableBody emptyContent={"No mesh health data."}>
        <>
          {health.map((item) => (
            <TableRow key={item.session_id}>
              <TableCell>
                <div className="flex flex-col">
                  <p className="text-sm font-semibold">{item.name}</p>
                  <p className="text-xs text-default-500">
                    #{item.agent_id} - {item.session_id}
                  </p>
                </div>
              </TableCell>
              <TableCell>
                <Chip color={meshStateColor(item.state)} size="sm" variant="flat">
                  {item.state}
                </Chip>
              </TableCell>
              <TableCell>
                <div className="flex flex-col text-xs text-default-500">
                  <span>Hop {item.hop_depth}</span>
                  <span>{item.path_rtt_ms ?? "-"} ms</span>
                  <span>{item.downstream_count} downstream</span>
                </div>
              </TableCell>
              <TableCell>
                <div className="flex max-w-[260px] flex-wrap gap-1">
                  {(item.issues ?? []).length > 0 ? (
                    item.issues?.map((issue) => (
                      <Chip key={issue} color="warning" size="sm" variant="flat">
                        {issue}
                      </Chip>
                    ))
                  ) : (
                    <span className="text-default-400">-</span>
                  )}
                </div>
              </TableCell>
              <TableCell>
                <div className="flex max-w-[320px] flex-col gap-1">
                  {(item.recovery_actions ?? []).length > 0 ? (
                    item.recovery_actions?.map((action) => (
                      <span key={action} className="text-xs text-default-500">
                        {action}
                      </span>
                    ))
                  ) : (
                    <span className="text-default-400">-</span>
                  )}
                </div>
              </TableCell>
            </TableRow>
          ))}
        </>
      </TableBody>
    </Table>
  );
}

function RoutePlanTable({ decisions }: { decisions: ChainRouteDecision[] }) {
  return (
    <Table aria-label="Smart route plan">
      <TableHeader>
        <TableColumn className="uppercase">Decision</TableColumn>
        <TableColumn className="uppercase">Agent</TableColumn>
        <TableColumn className="uppercase">Route</TableColumn>
        <TableColumn className="uppercase">Cost</TableColumn>
        <TableColumn className="uppercase">Reason</TableColumn>
      </TableHeader>
      <TableBody emptyContent={"No route plan available."}>
        <>
          {decisions.map((decision) => (
            <TableRow key={`${decision.agent_id}-${decision.route}`}>
              <TableCell>
                <div className="flex flex-col gap-1">
                  <Chip
                    color={decisionColor(decision.decision)}
                    size="sm"
                    variant="flat"
                  >
                    {decision.decision}
                  </Chip>
                  {decision.start_tunnel ? (
                    <span className="text-xs text-default-500">Start tunnel</span>
                  ) : null}
                </div>
              </TableCell>
              <TableCell>
                <div className="flex flex-col">
                  <p className="text-sm font-semibold">{decision.name}</p>
                  <p className="text-xs text-default-500">
                    #{decision.agent_id} - hop {decision.hop_depth}
                  </p>
                </div>
              </TableCell>
              <TableCell>
                <div className="flex flex-col">
                  <span>{decision.route}</span>
                  <span className="text-xs text-default-500">
                    {decision.interface}
                  </span>
                </div>
              </TableCell>
              <TableCell>
                <div className="flex flex-col text-xs text-default-500">
                  <span>{decision.score}</span>
                  <span>{decision.path_rtt_ms ?? "-"} ms</span>
                </div>
              </TableCell>
              <TableCell>
                <p className="max-w-[360px] text-sm text-default-500">
                  {decision.reason}
                </p>
              </TableCell>
            </TableRow>
          ))}
        </>
      </TableBody>
    </Table>
  );
}

function RepairPlanTable({ actions }: { actions: ChainRepairAction[] }) {
  return (
    <Table aria-label="Relay repair plan">
      <TableHeader>
        <TableColumn className="uppercase">Action</TableColumn>
        <TableColumn className="uppercase">Agent</TableColumn>
        <TableColumn className="uppercase">Target</TableColumn>
        <TableColumn className="uppercase">Apply</TableColumn>
        <TableColumn className="uppercase">Reason</TableColumn>
      </TableHeader>
      <TableBody emptyContent={"No repair actions pending."}>
        <>
          {actions.map((action, index) => (
            <TableRow
              key={`${action.type}-${action.agent_id ?? "global"}-${action.route ?? index}`}
            >
              <TableCell>
                <div className="flex flex-col gap-1">
                  <Chip color={severityColor(action.severity)} size="sm" variant="flat">
                    {action.type}
                  </Chip>
                  {action.error ? (
                    <span className="text-xs text-danger-500">{action.error}</span>
                  ) : null}
                </div>
              </TableCell>
              <TableCell>
                <div className="flex flex-col">
                  <p className="text-sm font-semibold">{action.name || "-"}</p>
                  {action.agent_id ? (
                    <p className="text-xs text-default-500">
                      #{action.agent_id} - {action.session_id}
                    </p>
                  ) : null}
                </div>
              </TableCell>
              <TableCell>
                <div className="flex flex-col">
                  <span>{action.route || "-"}</span>
                  <span className="text-xs text-default-500">
                    {action.interface || action.route_key || "-"}
                  </span>
                </div>
              </TableCell>
              <TableCell>
                <Chip
                  color={action.apply_supported ? "success" : "default"}
                  size="sm"
                  variant="flat"
                >
                  {action.applied
                    ? "applied"
                    : action.apply_supported
                      ? "supported"
                      : "manual"}
                </Chip>
              </TableCell>
              <TableCell>
                <p className="max-w-[360px] text-sm text-default-500">
                  {action.reason}
                </p>
              </TableCell>
            </TableRow>
          ))}
        </>
      </TableBody>
    </Table>
  );
}

function FailoverPlanTable({
  recommendations,
}: {
  recommendations: ChainFailoverRecommendation[];
}) {
  return (
    <Table aria-label="Relay failover plan">
      <TableHeader>
        <TableColumn className="uppercase">Agent</TableColumn>
        <TableColumn className="uppercase">Current Parent</TableColumn>
        <TableColumn className="uppercase">Recommended Parent</TableColumn>
        <TableColumn className="uppercase">Apply</TableColumn>
        <TableColumn className="uppercase">Reason</TableColumn>
      </TableHeader>
      <TableBody emptyContent={"No failover recommendations."}>
        <>
          {recommendations.map((recommendation) => (
            <TableRow key={recommendation.session_id}>
              <TableCell>
                <div className="flex flex-col">
                  <p className="text-sm font-semibold">{recommendation.name}</p>
                  <p className="text-xs text-default-500">
                    #{recommendation.agent_id} - hop {recommendation.hop_depth}
                  </p>
                </div>
              </TableCell>
              <TableCell>
                <div className="flex flex-col">
                  <span>{recommendation.current_parent_name || "-"}</span>
                  <span className="text-xs text-default-500">
                    {recommendation.current_parent_session_id}
                  </span>
                  {(recommendation.current_parent_issues ?? []).map((issue) => (
                    <Chip key={issue} color="warning" size="sm" variant="flat">
                      {issue}
                    </Chip>
                  ))}
                </div>
              </TableCell>
              <TableCell>
                {recommendation.recommended_parent ? (
                  <div className="flex flex-col">
                    <span>{recommendation.recommended_parent.name}</span>
                    <span className="text-xs text-default-500">
                      #{recommendation.recommended_parent.agent_id} - hop{" "}
                      {recommendation.recommended_parent.hop_depth}
                    </span>
                    <span className="text-xs text-default-500">
                      {recommendation.recommended_parent.path_rtt_ms ?? "-"} ms
                    </span>
                    <span className="text-xs text-default-500">
                      {recommendation.recommended_parent.reconnect_addr ?? "manual"}
                    </span>
                  </div>
                ) : (
                  <span className="text-default-400">-</span>
                )}
              </TableCell>
              <TableCell>
                <Chip
                  color={recommendation.apply_supported ? "success" : "default"}
                  size="sm"
                  variant="flat"
                >
                  {recommendation.applied
                    ? "applied"
                    : recommendation.apply_supported
                      ? "supported"
                      : recommendation.command_available
                        ? "command"
                        : "manual"}
                </Chip>
                {recommendation.error ? (
                  <p className="mt-1 text-xs text-danger-500">
                    {recommendation.error}
                  </p>
                ) : null}
              </TableCell>
              <TableCell>
                <p className="max-w-[360px] text-sm text-default-500">
                  {recommendation.reason}
                </p>
              </TableCell>
            </TableRow>
          ))}
        </>
      </TableBody>
    </Table>
  );
}

function RelayStartModal({
  agents,
  isOpen,
  mutate,
  mutateAgents,
  onOpenChange,
}: RelayStartModalProps) {
  const { post } = useApi();
  const { setError } = useContext(ErrorContext);
  const [selectedAgent, setSelectedAgent] = useState("");
  const [listenAddr, setListenAddr] = useState("0.0.0.0:11602");
  const [tokenTTLHours, setTokenTTLHours] = useState("8");
  const [oneTimeToken, setOneTimeToken] = useState(false);
  const [formErrors, setFormErrors] = useState<Record<string, string[]>>({});

  const relayCapableAgents = useMemo(
    () =>
      Object.entries<LigoloAgent>(agents ?? {}).filter(
        ([, agent]) => agent.RelayCapable,
      ),
    [agents],
  );

  const resetOnOpenChange = useCallback(() => {
    setSelectedAgent("");
    setListenAddr("0.0.0.0:11602");
    setTokenTTLHours("8");
    setOneTimeToken(false);
    setFormErrors({});
    if (onOpenChange) onOpenChange();
  }, [onOpenChange]);

  const startRelay = useCallback(
    (onClose: () => void) => async () => {
      const tokenTTL = Number(tokenTTLHours);
      const errors: Record<string, string[]> = {};
      if (!selectedAgent) errors.agent = ["Select an agent"];
      if (!listenAddr.trim()) errors.listenAddr = ["Enter a listen address"];
      if (!Number.isFinite(tokenTTL) || tokenTTL <= 0) {
        errors.tokenTTLHours = ["Enter a positive token TTL"];
      }
      if (Object.keys(errors).length > 0) {
        setFormErrors(errors);
        return;
      }
      setFormErrors({});

      try {
        const data = await post(`api/v1/relay/${selectedAgent}`, {
          ListenAddr: listenAddr,
          TokenTTLSeconds: Math.round(tokenTTL * 3600),
          OneTimeToken: oneTimeToken,
        });
        handleApiResponse(data as Parameters<typeof handleApiResponse>[0]);
        if (mutateAgents) await mutateAgents();
        if (mutate) await mutate();
        onClose();
      } catch (error) {
        setError(error);
      }
    },
    [
      listenAddr,
      mutate,
      mutateAgents,
      oneTimeToken,
      post,
      selectedAgent,
      setError,
      tokenTTLHours,
    ],
  );

  return (
    <Modal isOpen={isOpen} placement="top-center" onOpenChange={resetOnOpenChange}>
      <ModalContent>
        {(onClose) => (
          <>
            <ModalHeader className="flex flex-col gap-1">Start relay</ModalHeader>
            <ModalBody>
              <Form validationErrors={formErrors}>
                <Select
                  label="Relay agent"
                  name="agent"
                  placeholder="Select a relay-capable agent"
                  startContent={<Network size={18} />}
                  onSelectionChange={(keys) =>
                    setSelectedAgent(String(keys.currentKey ?? ""))
                  }
                >
                  {relayCapableAgents.map(([row, agent]) => (
                    <SelectItem
                      key={row}
                      textValue={`${agent.Name} - ${agent.SessionID}`}
                    >
                      {agent.Name} - {agent.SessionID}
                    </SelectItem>
                  ))}
                </Select>
                <Input
                  label="Listen address"
                  name="listenAddr"
                  placeholder="0.0.0.0:11602"
                  value={listenAddr}
                  variant="bordered"
                  onValueChange={setListenAddr}
                />
                <Input
                  label="Token TTL hours"
                  name="tokenTTLHours"
                  placeholder="8"
                  type="number"
                  value={tokenTTLHours}
                  variant="bordered"
                  onValueChange={setTokenTTLHours}
                />
                <Checkbox isSelected={oneTimeToken} onValueChange={setOneTimeToken}>
                  One-time relay token
                </Checkbox>
              </Form>
            </ModalBody>
            <ModalFooter>
              <Button color="danger" variant="flat" onPress={onClose}>
                Close
              </Button>
              <Button color="primary" onPress={startRelay(onClose)}>
                Start relay
              </Button>
            </ModalFooter>
          </>
        )}
      </ModalContent>
    </Modal>
  );
}

export default function RelayPage() {
  const { post, del } = useApi();
  const { setError } = useContext(ErrorContext);
  const { relayOps, loading, mutate } = useRelayOps();
  const { agents, mutate: mutateAgents } = useAgents();
  const {
    isOpen: isRelayStartOpen,
    onOpen: onRelayStartOpen,
    onOpenChange: onRelayStartOpenChange,
  } = useDisclosure();

  const relays = relayOps?.relays ?? [];
  const actions = relayOps?.actions ?? [];
  const warnings = relayOps?.warnings ?? [];
  const conflicts = (relayOps?.routes ?? []).filter((route) => route.conflict);
  const routePlan = relayOps?.route_plan;
  const meshHealth = relayOps?.mesh_health ?? [];
  const repairPlan = relayOps?.repair_plan;
  const failoverPlan = relayOps?.failover_plan;
  const autoHeal = relayOps?.auto_heal;

  const metricCards = useMemo(() => {
    const summary = relayOps?.summary;
    return [
      {
        icon: <Users size={16} />,
        label: "Agents",
        value: summary?.agents_total ?? 0,
        tone: "primary" as ChipColor,
      },
      {
        icon: <CheckCircle2 size={16} />,
        label: "Online",
        value: summary?.agents_online ?? 0,
        tone: "success" as ChipColor,
      },
      {
        icon: <Network size={16} />,
        label: "Active relays",
        value: summary?.active_relays ?? 0,
        tone: "primary" as ChipColor,
      },
      {
        icon: <GitBranch size={16} />,
        label: "Relayed agents",
        value: summary?.relayed_agents ?? 0,
        tone: "default" as ChipColor,
      },
      {
        icon: <Route size={16} />,
        label: "Plan apply",
        value: summary?.route_plan_apply ?? 0,
        tone: "success" as ChipColor,
      },
      {
        icon: <ListChecks size={16} />,
        label: "Plan skipped",
        value: summary?.route_plan_skipped ?? 0,
        tone: summary?.route_plan_skipped ? "warning" : ("default" as ChipColor),
      },
      {
        icon: <KeyRound size={16} />,
        label: "Expired tokens",
        value: summary?.expired_tokens ?? 0,
        tone: summary?.expired_tokens ? "danger" : ("default" as ChipColor),
      },
      {
        icon: <Wrench size={16} />,
        label: "Repairs",
        value: summary?.repair_actions ?? 0,
        tone: summary?.repair_actions ? "warning" : ("success" as ChipColor),
      },
      {
        icon: <GitBranch size={16} />,
        label: "Failovers",
        value: summary?.failover_recommendations ?? 0,
        tone: summary?.failover_recommendations
          ? "warning"
          : ("default" as ChipColor),
      },
      {
        icon: <AlertTriangle size={16} />,
        label: "Warnings",
        value: summary?.warnings ?? 0,
        tone: summary?.warnings ? "warning" : ("default" as ChipColor),
      },
      {
        icon: <ShieldCheck size={16} />,
        label: "Max depth",
        value: summary?.max_depth ?? 0,
        tone: "success" as ChipColor,
      },
    ];
  }, [relayOps]);

  const onRefresh = useCallback(async () => {
    await mutate();
  }, [mutate]);

  const onChainAutoroute = useCallback(async () => {
    try {
      const data = await post("api/v1/chain_autoroute", {
        InterfacePrefix: "ligolo",
        WithIPv6: false,
        Start: false,
      });
      handleApiResponse(data as Parameters<typeof handleApiResponse>[0]);
      await mutate();
    } catch (error) {
      setError(error);
    }
  }, [mutate, post, setError]);

  const onRotateToken = useCallback(
    (agentID: number) => async () => {
      try {
        const data = await post(`api/v1/relay/${agentID}/token`, {
          TokenTTLSeconds: 28800,
        });
        handleApiResponse(data as Parameters<typeof handleApiResponse>[0]);
        await mutate();
      } catch (error) {
        setError(error);
      }
    },
    [mutate, post, setError],
  );

  const onRevokeToken = useCallback(
    (agentID: number) => async () => {
      try {
        const data = await del(`api/v1/relay/${agentID}/token`);
        handleApiResponse(data as Parameters<typeof handleApiResponse>[0]);
        await mutate();
      } catch (error) {
        setError(error);
      }
    },
    [del, mutate, setError],
  );

  if (loading && !relayOps) {
    return (
      <section className="flex min-h-[320px] items-center justify-center py-8">
        <CircularProgress aria-label="Loading relay operations" size="sm" />
      </section>
    );
  }

  return (
    <>
      <RelayStartModal
        agents={agents}
        isOpen={isRelayStartOpen}
        mutate={mutate}
        mutateAgents={mutateAgents}
        onOpenChange={onRelayStartOpenChange}
      />
      <section className="flex flex-col gap-6 py-8 md:py-10">
        <div className="flex flex-col gap-4 md:flex-row md:items-start md:justify-between">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-3">
            <h1 className="text-2xl font-semibold tracking-normal">
              Relay operations
            </h1>
            <Chip
              color={statusColor(relayOps?.status ?? "warning")}
              size="sm"
              variant="flat"
            >
              {relayOps?.status ?? "loading"}
            </Chip>
          </div>
          <p className="mt-1 text-sm text-default-500">
            Updated {formatDate(relayOps?.generated_at)}
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Button
            color="default"
            startContent={<RefreshCw size={18} />}
            variant="flat"
            onPress={onRefresh}
          >
            Refresh
          </Button>
          <Button
            color="primary"
            startContent={<Route size={18} />}
            onPress={onChainAutoroute}
          >
            Apply plan
          </Button>
          <Button
            color="success"
            startContent={<Play size={18} />}
            onPress={onRelayStartOpen}
          >
            Start relay
          </Button>
        </div>
      </div>

      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        {metricCards.map((metric) => (
          <MetricCard
            key={metric.label}
            icon={metric.icon}
            label={metric.label}
            tone={metric.tone}
            value={metric.value}
          />
        ))}
      </div>

      <div className="grid gap-6 lg:grid-cols-[minmax(0,1.2fr)_minmax(320px,0.8fr)]">
        <section className="flex flex-col gap-3">
          <div className="flex items-center gap-2">
            <GitBranch size={18} />
            <h2 className="text-lg font-semibold">Chain topology</h2>
          </div>
          {relayOps?.chain.agents.length ? (
            <ul className="flex flex-col gap-2">
              {relayOps.chain.agents.map((node) => (
                <ChainNodeRow key={node.session_id} node={node} />
              ))}
            </ul>
          ) : (
            <div className="rounded-lg border border-default-200 px-4 py-6 text-sm text-default-500">
              No agents connected.
            </div>
          )}
        </section>

        <section className="flex flex-col gap-3">
          <div className="flex items-center gap-2">
            <Activity size={18} />
            <h2 className="text-lg font-semibold">Actions</h2>
          </div>
          {actions.length > 0 ? (
            <div className="flex flex-col gap-2">
              {actions.map((action) => (
                <ActionCard
                  key={`${action.title}-${action.agent_id ?? "global"}`}
                  action={action}
                />
              ))}
            </div>
          ) : (
            <div className="rounded-lg border border-default-200 px-4 py-6 text-sm text-default-500">
              No actions pending.
            </div>
          )}
        </section>
      </div>

      <section className="flex flex-col gap-3">
        <div className="flex flex-wrap items-center gap-2">
          <ShieldCheck size={18} />
          <h2 className="text-lg font-semibold">Auto-heal</h2>
          <Chip
            color={
              autoHeal?.policy.enabled
                ? autoHeal.policy.apply
                  ? "warning"
                  : "primary"
                : "default"
            }
            size="sm"
            variant="flat"
          >
            {autoHeal?.policy.enabled
              ? autoHeal.policy.apply
                ? "apply"
                : "monitor"
              : "disabled"}
          </Chip>
          {autoHeal?.running ? (
            <Chip color="primary" size="sm" variant="dot">
              running
            </Chip>
          ) : null}
        </div>
        <div className="grid gap-3 md:grid-cols-3">
          <div className="rounded-lg border border-default-200 px-4 py-3">
            <p className="text-xs uppercase text-default-500">Interval</p>
            <p className="mt-1 text-sm font-medium">
              {autoHeal?.policy.interval_seconds ?? 0}s
            </p>
          </div>
          <div className="rounded-lg border border-default-200 px-4 py-3">
            <p className="text-xs uppercase text-default-500">Last run</p>
            <p className="mt-1 text-sm font-medium">
              {autoHeal?.last_run
                ? `${autoHeal.last_run.status} / ${autoHeal.last_run.applied} applied`
                : "none"}
            </p>
          </div>
          <div className="rounded-lg border border-default-200 px-4 py-3">
            <p className="text-xs uppercase text-default-500">Next run</p>
            <p className="mt-1 text-sm font-medium">
              {formatDate(autoHeal?.next_run_at)}
            </p>
          </div>
        </div>
      </section>

      <section className="flex flex-col gap-3">
        <div className="flex items-center gap-2">
          <Wrench size={18} />
          <h2 className="text-lg font-semibold">Mesh health</h2>
        </div>
        <MeshHealthTable health={meshHealth} />
      </section>

      <section className="flex flex-col gap-3">
        <div className="flex items-center gap-2">
          <ListChecks size={18} />
          <h2 className="text-lg font-semibold">Smart route plan</h2>
          {routePlan ? (
            <Chip color={statusColor(routePlan.status)} size="sm" variant="flat">
              {routePlan.summary.apply} apply / {routePlan.summary.skipped} skip
            </Chip>
          ) : null}
        </div>
        <RoutePlanTable decisions={routePlan?.decisions ?? []} />
      </section>

      <section className="flex flex-col gap-3">
        <div className="flex items-center gap-2">
          <Wrench size={18} />
          <h2 className="text-lg font-semibold">Repair plan</h2>
          {repairPlan ? (
            <Chip color={statusColor(repairPlan.status)} size="sm" variant="flat">
              {repairPlan.summary.apply_supported} automatic /{" "}
              {repairPlan.summary.manual} manual
            </Chip>
          ) : null}
        </div>
        <RepairPlanTable actions={repairPlan?.actions ?? []} />
      </section>

      <section className="flex flex-col gap-3">
        <div className="flex items-center gap-2">
          <GitBranch size={18} />
          <h2 className="text-lg font-semibold">Failover plan</h2>
          {failoverPlan ? (
            <Chip color={statusColor(failoverPlan.status)} size="sm" variant="flat">
              {failoverPlan.summary.recommendations} recommended /{" "}
              {failoverPlan.summary.apply_supported} apply-ready
            </Chip>
          ) : null}
        </div>
        <FailoverPlanTable
          recommendations={failoverPlan?.recommendations ?? []}
        />
      </section>

      <section className="flex flex-col gap-3">
        <div className="flex items-center gap-2">
          <RotateCcw size={18} />
          <h2 className="text-lg font-semibold">Relay controls</h2>
        </div>
        <RelayControlsTable
          relays={relays}
          onRevokeToken={onRevokeToken}
          onRotateToken={onRotateToken}
        />
      </section>

      <section className="flex flex-col gap-3">
        <div className="flex items-center gap-2">
          <AlertTriangle size={18} />
          <h2 className="text-lg font-semibold">Route conflicts</h2>
        </div>
        <RouteConflictTable routes={conflicts} />
      </section>

      {warnings.length > 0 ? (
        <section className="flex flex-col gap-3">
          <div className="flex items-center gap-2">
            <AlertTriangle size={18} />
            <h2 className="text-lg font-semibold">Warnings</h2>
          </div>
          <div className="flex flex-col gap-2">
            {warnings.map((warning) => (
              <div
                key={warning}
                className="rounded-lg border border-warning-200 bg-warning-50 px-4 py-3 text-sm text-warning-700 dark:border-warning-100/20 dark:bg-warning-900/20 dark:text-warning-300"
              >
                {warning}
              </div>
            ))}
          </div>
        </section>
      ) : null}
      </section>
    </>
  );
}
