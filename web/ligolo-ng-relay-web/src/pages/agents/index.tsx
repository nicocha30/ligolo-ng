import { useCallback, useContext, useState } from "react";
import {
  Chip,
  Table,
  TableBody,
  TableCell,
  TableColumn,
  TableHeader,
  TableRow,
  useDisclosure,
} from "@heroui/react";
import ErrorContext from "@/contexts/Error.tsx";
import { LigoloAgent, LigoloAgentList } from "@/types/agents.ts";
import useAgents from "@/hooks/useAgents.ts";
import useInterfaces from "@/hooks/useInterfaces.ts";
import { InterfaceCreationModal } from "@/pages/interfaces/modal.tsx";
import { handleApiResponse } from "@/hooks/toast.ts";
import { AutorouteModal } from "@/pages/agents/modal.tsx";
import { useApi } from "@/hooks/useApi.ts";
import { AgentActions, AgentInterfaceList } from "@/pages/agents/agentRow.tsx";
import { AgentTableContext } from "@/pages/agents/contexts/agentTableContext.ts";

export default function AgentPage() {
  const { post, del } = useApi();
  const { setError } = useContext(ErrorContext);

  const { agents, loading, mutate: mutateAgent } = useAgents();
  const { mutate: mutateInterface } = useInterfaces();
  const {
    onOpen: onOpenInterfaceCreationModal,
    isOpen: isInterfaceCreationModalOpen,
    onOpenChange: onInterfaceCreationModalOpenChange,
  } = useDisclosure();

  const {
    onOpen: onAutorouteOpen,
    isOpen: isAutorouteModalOpen,
    onOpenChange: onAutorouteModalOpenChange,
  } = useDisclosure();

  const [selectedAgent, setSelectedAgent] = useState<keyof LigoloAgentList>(0);
  const [agentExpand, setAgentExpand] = useState<keyof LigoloAgentList | null>(
    null,
  );

  const loadingState = loading ? "loading" : "idle";

  const toggleAgentExpand = (row: number) => {
    setAgentExpand((agent) => (agent === row ? null : row));
  };

  const onTunnelStop = useCallback(
    (id: string) => async () => {
      try {
        const data = await del(`api/v1/tunnel/${id}`);
        // TODO validate response
        handleApiResponse(data as Parameters<typeof handleApiResponse>[0]);

        if (mutateAgent) await mutateAgent();
      } catch (error) {
        setError(error);
      }
    },
    [mutateAgent],
  );

  const onTunnelStart = useCallback(
    (id: string, iface: string) => async () => {
      try {
        const data = await post(`api/v1/tunnel/${id}`, { interface: iface });
        // TODO validate response
        handleApiResponse(data as Parameters<typeof handleApiResponse>[0]);

        if (mutateAgent) await mutateAgent();
      } catch (error) {
        setError(error);
      }
    },
    [mutateAgent],
  );

  const onInterfaceCreated = useCallback(
    async (interfaceName?: string) => {
      onInterfaceCreationModalOpenChange();

      if (interfaceName)
        await onTunnelStart(`${selectedAgent}`, interfaceName)();
      if (mutateAgent) await mutateAgent();
    },
    [onInterfaceCreationModalOpenChange, selectedAgent, mutateAgent],
  );

  const onAutorouteModal = useCallback(
    (row: number) => async () => {
      setSelectedAgent(row);
      onAutorouteOpen();
    },
    [],
  );
  const onInterfaceModal = useCallback(
    (row: number) => async () => {
      setSelectedAgent(row);
      onOpenInterfaceCreationModal();
    },
    [],
  );

  return (
    <AgentTableContext.Provider
      value={{
        onTunnelStop,
        onTunnelStart,
        onAutorouteModal,
        onInterfaceModal,
        toggleAgentExpand,
        agentExpand,
      }}
    >
      <InterfaceCreationModal
        mutate={mutateInterface}
        onOpenChange={onInterfaceCreated}
        isOpen={isInterfaceCreationModalOpen}
      />
      <AutorouteModal
        mutate={mutateAgent}
        onOpenChange={onAutorouteModalOpenChange}
        isOpen={isAutorouteModalOpen}
        selectedAgent={selectedAgent}
      />

      <section className="flex flex-col items-center justify-center gap-4 py-8 md:py-10">
        <Table aria-label="Table with agent list" rowHeight={60}>
          <TableHeader>
            <TableColumn>#</TableColumn>
            <TableColumn className="uppercase">Name</TableColumn>
            <TableColumn className="uppercase">Interface</TableColumn>
            <TableColumn className="uppercase">Status</TableColumn>
            <TableColumn className="uppercase">Actions</TableColumn>
          </TableHeader>
          <TableBody
            loadingState={loadingState}
            emptyContent={"No agents connected."}
          >
            <>
              {agents
                ? Object.entries<LigoloAgent>(agents).map(([row, agent]) => (
                    <>
                      <TableRow key={row} className="h-[60px] relative z-10">
                        <TableCell>{row}</TableCell>
                        <TableCell>
                          <div className="flex flex-col">
                            <p className="text-bold text-sm">{agent.Name}</p>
                            <p className="text-bold text-sm text-default-400">
                              {agent.RemoteAddr} - {agent.SessionID}
                            </p>
                          </div>
                        </TableCell>
                        <TableCell>
                          <div className="flex flex-col">
                            <p className="text-bold text-sm">
                              {agent.Interface}
                            </p>
                          </div>
                        </TableCell>
                        <TableCell>
                          <Chip
                            className="capitalize"
                            color={agent.Running ? "success" : "danger"}
                            size="sm"
                            variant="flat"
                          >
                            {agent.Running ? "Tunneling" : "Stopped"}
                          </Chip>
                        </TableCell>
                        <TableCell>
                          <AgentActions row={row} agent={agent} />
                        </TableCell>
                      </TableRow>
                      <TableRow className="z-0">
                        <TableCell className="p-0" colSpan={5}>
                          <AgentInterfaceList
                            open={row === `${agentExpand}`}
                            agent={agent}
                          />
                        </TableCell>

                        {/* HeroUI doesn't seems to support colspan properly */}
                        <TableCell children={null} className={"hidden"} />
                        <TableCell children={null} className={"hidden"} />
                        <TableCell children={null} className={"hidden"} />
                        <TableCell children={null} className={"hidden"} />
                      </TableRow>
                    </>
                  ))
                : null}
            </>
          </TableBody>
        </Table>
      </section>
    </AgentTableContext.Provider>
  );
}
