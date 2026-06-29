import { createContext } from "react";

export interface IAgentTableContext {
  onTunnelStop: (id: string) => () => Promise<void>;
  onTunnelStart: (id: string, iface: string) => () => Promise<void>;
  onAutorouteModal: (row: number) => () => Promise<void>;
  onInterfaceModal: (row: number) => () => Promise<void>;
  toggleAgentExpand: (row: number) => void;
  agentExpand: number | null;
}

const stateNotReady = () =>
  new Promise<void>(() =>
    console.warn(
      "State was not ready when a AgentTableContext method was called",
    ),
  );

export const AgentTableContext = createContext<IAgentTableContext>({
  onTunnelStop: () => stateNotReady,
  onTunnelStart: () => stateNotReady,
  onAutorouteModal: () => stateNotReady,
  onInterfaceModal: () => stateNotReady,
  toggleAgentExpand: stateNotReady,
  agentExpand: null,
});
