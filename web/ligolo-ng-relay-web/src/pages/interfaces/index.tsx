import { useCallback, useState } from "react";
import {
  Button,
  Chip,
  CircularProgress,
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
  CheckIcon,
  CircleX,
  EthernetPort,
  HourglassIcon,
  PlusIcon,
} from "lucide-react";
import useInterfaces from "@/hooks/useInterfaces.ts";
import {
  InterfaceCreationModal,
  RouteCreationModal,
} from "@/pages/interfaces/modal.tsx";
import { LigoloInterfaces } from "@/types/interfaces.ts";
import { useApi } from "@/hooks/useApi.ts";

export default function IndexPage() {
  const { interfaces, loading, mutate } = useInterfaces();
  const { del } = useApi();

  const onRouteDelete = useCallback(
    (iface: string, route: string) => async () => {
      await del(`api/v1/routes`, {
        interface: iface,
        route,
      }); // TODO check API response

      await mutate();
    },
    [mutate],
  );

  const onInterfaceDelete = useCallback(
    (iface: string) => async () => {
      await del(`api/v1/interfaces`, {
        interface: iface,
      }); // TODO check API response

      await mutate();
    },
    [mutate],
  );

  const { isOpen, onOpen, onOpenChange } = useDisclosure();

  const {
    isOpen: isInterfaceOpen,
    onOpen: onInterfaceOpen,
    onOpenChange: onInterfaceOpenChange,
  } = useDisclosure();

  const [selectedInterface, setSelectedInterface] = useState("");

  return (
    <>
      <InterfaceCreationModal
        isOpen={isInterfaceOpen}
        onOpenChange={onInterfaceOpenChange}
        mutate={mutate}
      ></InterfaceCreationModal>
      <RouteCreationModal
        isOpen={isOpen}
        onOpenChange={onOpenChange}
        selectedInterface={selectedInterface}
        mutate={mutate}
      ></RouteCreationModal>

      <section className="flex flex-col gap-4 md:py-10">
        <div className="flex justify-between gap-3 items-end">
          <Button
            color="primary"
            endContent={<PlusIcon />}
            onPress={onInterfaceOpen}
          >
            Add New
          </Button>
        </div>
        <Table aria-label="Interface list">
          <TableHeader>
            <TableColumn className="uppercase">Interface Name</TableColumn>
            <TableColumn className="uppercase">State</TableColumn>
            <TableColumn className="uppercase">Routes</TableColumn>
            <TableColumn className="uppercase">Actions</TableColumn>
          </TableHeader>
          <TableBody
            loadingState={loading ? "loading" : "idle"}
            emptyContent={"No interfaces connected."}
            loadingContent={
              <CircularProgress aria-label="Loading..." size="sm" />
            }
          >
            <>
              {interfaces
                ? Object.entries<LigoloInterfaces[number]>(interfaces).map(
                    ([row, iface]) => (
                      <TableRow key={row}>
                        <TableCell>{row}</TableCell>
                        <TableCell>
                          {iface.Active ? (
                            <Chip
                              color="success"
                              startContent={<CheckIcon size={18} />}
                              variant="faded"
                            >
                              <Tooltip
                                content="Active interfaces are already present on the system"
                                color={"success"}
                              >
                                Active
                              </Tooltip>
                            </Chip>
                          ) : (
                            <Chip
                              color="warning"
                              startContent={<HourglassIcon size={18} />}
                              variant="faded"
                            >
                              <Tooltip
                                content="Pending interfaces will be created on tunnel start"
                                color={"warning"}
                              >
                                Pending
                              </Tooltip>
                            </Chip>
                          )}
                        </TableCell>
                        <TableCell>
                          <div className="flex flex-wrap gap-1">
                            {iface.Routes
                              ? iface.Routes.map((route, idx) => (
                                  <Chip
                                    key={idx}
                                    color={route.Active ? "success" : "warning"}
                                    variant="flat"
                                    onClose={onRouteDelete(
                                      row,
                                      route.Destination,
                                    )}
                                  >
                                    {route.Destination}
                                  </Chip>
                                ))
                              : null}
                          </div>
                        </TableCell>
                        <TableCell>
                          <div className="relative flex items-center gap-2">
                            <Tooltip content="Add new route">
                              <span
                                className="text-lg text-default-400 cursor-pointer active:opacity-50"
                                onClick={() => {
                                  setSelectedInterface(row);
                                  onOpen();
                                }}
                              >
                                <EthernetPort />
                              </span>
                            </Tooltip>
                            <Tooltip
                              content="Remove interface"
                              color={"danger"}
                            >
                              <span
                                className="text-lg text-danger cursor-pointer active:opacity-50"
                                onClick={onInterfaceDelete(row)}
                              >
                                <CircleX />
                              </span>
                            </Tooltip>
                          </div>
                        </TableCell>
                      </TableRow>
                    ),
                  )
                : null}
            </>
          </TableBody>
        </Table>
      </section>
    </>
  );
}
