import { ThemeSwitch } from "@/components/theme-switch.tsx";
import { Card, Progress } from "@heroui/react";
import { Logo } from "@/assets/icons/logo.tsx";

export default function LoadingPage() {
  return (
    <div className="h-[100vh] flex items-center">
      <div className="absolute top-0 right-0 p-4">
        <ThemeSwitch />
      </div>
      <Card className="w-[600px] flex m-auto p-6 !transition-none">
        <div className="inline-flex  text-default-foreground items-center gap-1 justify-center mb-2 select-none">
          <Logo size={50} />
          <p className="font-bold font-[500] text-xl tracking-wider flex items-center gap-[1px] opacity-90">
            Ligolo-ng Relay
          </p>
        </div>
        <div className="mt-6">
          <Progress
            classNames={{
              track: "drop-shadow-md border border-default",
              indicator: "bg-gradient-to-r from-red-500 to-red-800",
              label: "tracking-wider font-medium text-default-600",
              value: "text-foreground/60",
            }}
            radius="sm"
            size="sm"
            value={100}
          />
        </div>
      </Card>
    </div>
  );
}
