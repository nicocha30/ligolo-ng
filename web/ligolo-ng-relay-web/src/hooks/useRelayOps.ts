import { useApi } from "@/hooks/useApi.ts";
import { RelayOpsReport } from "@/types/relay.ts";

export default function useRelayOps() {
  const { swr } = useApi();
  const { data, mutate, isLoading } =
    swr<RelayOpsReport>("api/v1/relay/ops");

  return { relayOps: data, loading: isLoading, mutate };
}
