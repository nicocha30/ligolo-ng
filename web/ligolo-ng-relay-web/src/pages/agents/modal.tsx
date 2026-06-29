import { useApi } from "@/hooks/useApi.ts";
import { useCallback, useContext, useState } from "react";
import ErrorContext from "@/contexts/Error.tsx";
import { generateSlug } from "random-word-slugs";
import {
  addToast,
  Button,
  Card,
  CardBody,
  Checkbox,
  CheckboxGroup,
  Input,
  Modal,
  ModalBody,
  ModalContent,
  ModalFooter,
  ModalHeader,
  Select,
  SelectItem,
  Tab,
  Tabs,
} from "@heroui/react";
import { DicesIcon, NetworkIcon } from "lucide-react";
import useAgents from "@/hooks/useAgents.ts";
import { LigoloAgentList } from "@/types/agents.ts";
import useInterfaces from "@/hooks/useInterfaces.ts";

interface InterfaceCreationProps {
  isOpen?: boolean;
  onOpenChange?: () => void;
  selectedAgent: keyof LigoloAgentList;
  mutate?: () => Promise<unknown>;
}

export function AutorouteModal({
  isOpen,
  onOpenChange,
  selectedAgent,
  mutate,
}: InterfaceCreationProps) {
  const { post } = useApi();
  const { agents } = useAgents();
  const { interfaces } = useInterfaces();
  const [interfaceName, setInterfaceName] = useState<string | undefined>("");
  const [showIPv6, setShowIPv6] = useState(false);
  const [selectedRoutes, setSelectedRoutes] = useState<string[]>([]);
  const [selectedTab, setSelectedTab] = useState<string | number>("");
  const { setError } = useContext(ErrorContext);

  const randInterfaceName = useCallback(
    () => setInterfaceName(generateSlug(2).replace("-", "").substring(0, 15)),
    [],
  );

  const isLoopbackAddr = function (ip: string) {
    return (
      /^127\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})/i.test(ip) ||
      /^::1/.test(ip)
    );
  };

  const isIPv6 = function (ip: string) {
    return /(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]+|::(ffff(:0{1,4})?:)?((25[0-5]|(2[0-4]|1?[0-9])?[0-9])\.){3}(25[0-5]|(2[0-4]|1?[0-9])?[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1?[0-9])?[0-9])\.){3}(25[0-5]|(2[0-4]|1?[0-9])?[0-9]))/.test(
      ip,
    );
  };

  const setupAutoroute = useCallback(async () => {
    if (selectedTab === "createInterface") {
      await post("api/v1/interfaces", {
        interface: interfaceName,
      }).catch(setError);
    }
    await post("api/v1/routes", {
      interface: interfaceName,
      route: selectedRoutes,
    }).catch(setError);

    if (mutate) await mutate();
  }, [mutate, interfaceName, selectedRoutes]);

  const refreshOnOpen = useCallback(async () => {
    setInterfaceName("");

    if (onOpenChange) return onOpenChange();
  }, [onOpenChange]);

  return (
    <Modal isOpen={isOpen} placement="top-center" onOpenChange={refreshOnOpen}>
      <ModalContent>
        {(onClose) => (
          <>
            <ModalHeader className="flex flex-col gap-1">Autoroute</ModalHeader>
            <ModalBody>
              <div className="flex flex-col w-full">
                <Card>
                  <CardBody className="overflow-hidden">
                    <Tabs
                      fullWidth
                      aria-label="Tabs form"
                      size="md"
                      onSelectionChange={setSelectedTab}
                      selectedKey={selectedTab}
                    >
                      <Tab key="createInterface" title="Create a new interface">
                        <div className={"flex py-2 px-1 justify-between gap-2"}>
                          <Input
                            endContent={
                              <NetworkIcon className="text-2xl text-default-400 pointer-events-none flex-shrink-0" />
                            }
                            label="Interface name"
                            placeholder="Enter the new interface name"
                            variant="bordered"
                            type={"text"}
                            maxLength={15}
                            value={interfaceName}
                            onValueChange={setInterfaceName}
                          />
                          <Button
                            isIconOnly
                            aria-label="Like"
                            color="danger"
                            className={"min-w-14 w-14 h-14"}
                            onPress={randInterfaceName}
                          >
                            <DicesIcon />
                          </Button>
                        </div>
                      </Tab>
                      <Tab key="useInterface" title="Use an existing interface">
                        <div className={"flex py-2 px-1 justify-between gap-2"}>
                          <Select
                            label="Interface"
                            placeholder="Select an interface"
                            startContent={<NetworkIcon />}
                            onSelectionChange={(value) =>
                              setInterfaceName(value.currentKey)
                            }
                          >
                            {interfaces
                              ? Object.keys(interfaces).map((ifName) => (
                                  <SelectItem key={ifName}>{ifName}</SelectItem>
                                ))
                              : null}
                          </Select>
                        </div>
                      </Tab>
                    </Tabs>
                    <div className={"pb-3"}>
                      <Checkbox
                        key={"includeIPv6"}
                        onValueChange={setShowIPv6}
                        defaultChecked={showIPv6}
                      >
                        Display IPv6 routes
                      </Checkbox>
                    </div>
                    <CheckboxGroup
                      label="Select routes to add to the interface"
                      onValueChange={setSelectedRoutes}
                      value={selectedRoutes}
                    >
                      {agents
                        ? agents[selectedAgent].Network.map((network) =>
                            network.Addresses?.filter(
                              (address) =>
                                !isLoopbackAddr(address) &&
                                (showIPv6 || !isIPv6(address)),
                            ).map((address) => (
                              <Checkbox value={address} key={address}>
                                {address}
                              </Checkbox>
                            )),
                          )
                        : ""}
                    </CheckboxGroup>
                  </CardBody>
                </Card>
              </div>
            </ModalBody>
            <ModalFooter>
              <Button color="danger" onPress={onClose}>
                Close
              </Button>
              <Button
                color="warning"
                onPress={async () => {
                  await setupAutoroute().then(() => {
                    addToast({
                      title: "Ligolo-ng Relay",
                      description:
                        "Autoroute: interface and routes configured!",
                      color: "success",
                    });
                  });
                  onClose();
                }}
              >
                Setup routes
              </Button>
              <Button
                color="success"
                onPress={async () => {
                  try {
                    await setupAutoroute();
                    await post(`api/v1/tunnel/${selectedAgent}`, {
                      interface: interfaceName,
                    });

                    addToast({
                      title: "Ligolo-ng Relay",
                      description: "Autoroute: tunnel started!",
                      color: "success",
                    });
                  } catch (error) {
                    setError(error);
                  }

                  onClose();
                }}
              >
                Setup routes and start tunnel
              </Button>
            </ModalFooter>
          </>
        )}
      </ModalContent>
    </Modal>
  );
}
