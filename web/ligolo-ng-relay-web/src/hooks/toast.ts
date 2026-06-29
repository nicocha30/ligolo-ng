import { addToast } from "@heroui/react";

type ApiResponse = Record<string, unknown> & {
  message: string;
  error: string;
};

export function handleApiResponse(jsonData: ApiResponse): void {
  if (!jsonData.error && !jsonData.message) return;
  addToast({
    title: "Ligolo-ng Relay",
    description: jsonData.error || jsonData.message,
    color: jsonData.error ? "danger" : "success",
  });
}
