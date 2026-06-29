import { useCallback, useContext, useState } from "react";
import {
  Button,
  Form,
  Input,
  Modal,
  ModalBody,
  ModalContent,
  ModalFooter,
  ModalHeader,
} from "@heroui/react";
import { DicesIcon, EthernetPort, NetworkIcon } from "lucide-react";
import { generateSlug } from "random-word-slugs";
import { useApi } from "@/hooks/useApi.ts";
import ErrorContext from "@/contexts/Error.tsx";
import { interfaceRouteSchema, interfaceSchema } from "@/schemas/interfaces.ts";

interface RouteCreationProps {
  isOpen?: boolean;
  onOpenChange?: () => void;
  selectedInterface?: string | undefined;
  mutate?: () => Promise<unknown>;
}

export function RouteCreationModal({
  isOpen,
  onOpenChange,
  selectedInterface,
  mutate,
}: RouteCreationProps) {
  const { setError } = useContext(ErrorContext);
  const [route, setRoute] = useState("");
  const { post } = useApi();
  const [formErrors, setFormErrors] = useState({});

  const createRoute = useCallback(
    (onClose: () => void) => async () => {
      const result = interfaceRouteSchema.safeParse({
        interface: selectedInterface,
        routes: [route],
      });
      if (!result.success) {
        setFormErrors(result.error.flatten().fieldErrors);
        return;
      }
      setFormErrors({});

      await post("api/v1/routes", {
        interface: selectedInterface,
        route: [route],
      }).catch(setError);
      // TODO validate response
      if (mutate) await mutate();
      onClose();
    },
    [route, mutate, selectedInterface, post],
  );

  return (
    <Modal isOpen={isOpen} placement="top-center" onOpenChange={onOpenChange}>
      <ModalContent>
        {(onClose) => (
          <>
            <ModalHeader className="flex flex-col gap-1">
              Setup new route to {selectedInterface}
            </ModalHeader>
            <ModalBody>
              <Form validationErrors={formErrors}>
                <Input
                  endContent={
                    <EthernetPort className="text-2xl text-default-400 pointer-events-none flex-shrink-0" />
                  }
                  label="Route"
                  placeholder="Enter the new route to add to the interface"
                  variant="bordered"
                  type="text"
                  name={"routes"}
                  value={route}
                  onValueChange={setRoute}
                />
              </Form>
            </ModalBody>
            <ModalFooter>
              <Button color="danger" variant="flat" onPress={onClose}>
                Close
              </Button>
              <Button color="success" onPress={createRoute(onClose)}>
                Add route
              </Button>
            </ModalFooter>
          </>
        )}
      </ModalContent>
    </Modal>
  );
}

interface InterfaceCreationProps {
  isOpen?: boolean;
  onOpenChange?: (interfaceName: string) => void;
  mutate?: () => Promise<unknown>;
}

export function InterfaceCreationModal({
  isOpen,
  onOpenChange,
  mutate,
}: InterfaceCreationProps) {
  const { post } = useApi();

  const [interfaceName, setInterfaceName] = useState("");
  const { setError } = useContext(ErrorContext);
  const [formErrors, setFormErrors] = useState({});

  const randInterfaceName = useCallback(
    () => setInterfaceName(generateSlug(2).replace("-", "").substring(0, 15)),
    [],
  );

  const addInterface = useCallback(
    (onClose: () => void) => async () => {
      const result = interfaceSchema.safeParse({ interface: interfaceName });
      if (!result.success) {
        setFormErrors(result.error.flatten().fieldErrors);
        return;
      }
      setFormErrors({});

      await post("api/v1/interfaces", { interface: interfaceName }).catch(
        setError,
      );
      if (mutate) mutate();
      onClose();
    },
    [mutate, interfaceName],
  );

  const refreshOnOpen = useCallback(async () => {
    setInterfaceName("");

    if (onOpenChange) return onOpenChange(interfaceName);
  }, [onOpenChange, interfaceName]);

  return (
    <Modal isOpen={isOpen} placement="top-center" onOpenChange={refreshOnOpen}>
      <ModalContent>
        {(onClose) => (
          <>
            <ModalHeader className="flex flex-col gap-1">
              Interface creation
            </ModalHeader>
            <Form validationErrors={formErrors}>
              <ModalBody className={"w-full"}>
                <div className={"flex py-2 px-1 justify-between gap-2 w-full"}>
                  <Input
                    endContent={
                      <NetworkIcon className="text-2xl text-default-400 pointer-events-none flex-shrink-0" />
                    }
                    label="Interface name"
                    placeholder="Enter the new interface name"
                    variant="bordered"
                    type={"text"}
                    name={"interface"}
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
              </ModalBody>
            </Form>
            <ModalFooter>
              <Button color="danger" variant="flat" onPress={onClose}>
                Close
              </Button>
              <Button color="success" onPress={addInterface(onClose)}>
                Create interface
              </Button>
            </ModalFooter>
          </>
        )}
      </ModalContent>
    </Modal>
  );
}
