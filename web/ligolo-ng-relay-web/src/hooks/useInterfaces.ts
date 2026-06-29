import { LigoloInterfaces } from "@/types/interfaces.ts";
import { useApi } from "@/hooks/useApi.ts";

export default function useInterfaces() {
  const { swr } = useApi();
  const { data, mutate, isLoading } = swr<LigoloInterfaces>("api/v1/interfaces");

  return { interfaces: data, loading: isLoading, mutate };
}
