import { LigoloAgent } from "@/types/agents.ts";
import {
  Accordion,
  AccordionItem,
  Button,
  Chip,
  Divider,
  Dropdown,
  DropdownItem,
  DropdownMenu,
  DropdownTrigger,
  Table,
  TableBody,
  TableCell,
  TableColumn,
  TableHeader,
  TableRow,
  Tooltip,
} from "@heroui/react";
import {
  ChevronDown,
  ChevronLeft,
  ChevronsLeftRightEllipsis,
  FileCog,
  NetworkIcon,
  Power,
  PowerOff,
} from "lucide-react";
import useInterfaces from "@/hooks/useInterfaces.ts";
import { useContext } from "react";
import { AgentTableContext } from "@/pages/agents/contexts/agentTableContext.ts";

interface IAgentActionsProps {
  agent: LigoloAgent;
  row: string;
}

export const AgentActions = ({ agent, row }: IAgentActionsProps) => {
  const { interfaces } = useInterfaces();
  const {
    onTunnelStart,
    onTunnelStop,
    onInterfaceModal,
    onAutorouteModal,
    toggleAgentExpand,
    agentExpand,
  } = useContext(AgentTableContext);

  return (
    <div className="relative flex justify-between">
      <div className="flex items-center gap-2">
        <Button size="sm" isIconOnly onPress={onAutorouteModal(parseInt(row))}>
          <Tooltip content={"Autoroute"}>
            <FileCog size={15} />
          </Tooltip>
        </Button>
        <Dropdown>
          {agent.Running ? (
            <Button
              color={"danger"}
              size="sm"
              isIconOnly
              onPress={onTunnelStop(row)}
            >
              <Tooltip color={"danger"} content={"Stop tunneling"}>
                <PowerOff size={15} />
              </Tooltip>
            </Button>
          ) : (
            <DropdownTrigger>
              <Button color={"default"} size="sm" isIconOnly>
                <Tooltip color={"default"} content={"Setup tunneling"}>
                  <Power size={15} />
                </Tooltip>
              </Button>
            </DropdownTrigger>
          )}

          {!agent.Running && (
            <>
              <DropdownMenu aria-label="Static Actions">
                <>
                  <DropdownItem
                    key="new"
                    startContent={
                      <NetworkIcon className="text-xl text-default-500 pointer-events-none flex-shrink-0" />
                    }
                    showDivider={
                      !!(interfaces && Object.keys(interfaces).length)
                    }
                    description="Create a random interface then start the tunnel"
                    onPress={onInterfaceModal(parseInt(row))}
                  >
                    Start with a new interface
                  </DropdownItem>
                  {interfaces &&
                    Object.keys(interfaces).map((ifName) => (
                      <DropdownItem
                        key={ifName}
                        startContent={
                          <ChevronsLeftRightEllipsis className="text-xl text-default-500 pointer-events-none flex-shrink-0" />
                        }
                        description="Use the following interface"
                        onPress={onTunnelStart(row, ifName)}
                      >
                        Bind to {ifName}
                      </DropdownItem>
                    ))}
                </>
              </DropdownMenu>
            </>
          )}
        </Dropdown>
      </div>
      <Button
        size="sm"
        isIconOnly
        onPress={() => toggleAgentExpand(parseInt(row))}
      >
        {row === `${agentExpand}` ? (
          <ChevronDown size={15} />
        ) : (
          <ChevronLeft size={15} />
        )}
      </Button>
    </div>
  );
};

interface AgentInterfaceListProps {
  agent: LigoloAgent;
  open: boolean;
}

export const AgentInterfaceList = ({
  agent,
  open,
}: AgentInterfaceListProps) => {
  return (
    <Accordion selectedKeys={open ? ["1"] : []} className="-mt-[50px]">
      <AccordionItem key="1" indicator={<></>}>
        <Divider className="mt-4" />
        <Table removeWrapper hideHeader className="flex flex-col p-2">
          <TableHeader>
            <TableColumn>Name</TableColumn>
            <TableColumn>Ifaces</TableColumn>
          </TableHeader>
          <TableBody>
            {agent.Network.map((network) => (
              <TableRow key={network.Name} className="flex items-center ">
                <TableCell> {network.Name}: </TableCell>
                <TableCell className="flex gap-2">
                  {network.Addresses
                    ? network.Addresses.map((net) => (
                        <Chip size="sm" key={net}>
                          {net}
                        </Chip>
                      ))
                    : null}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </AccordionItem>
    </Accordion>
  );
};
