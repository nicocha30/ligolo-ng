import { z } from "zod";

export const ipPortSchema = z
  .string()
  .trim()
  .superRefine((value, ctx) => {
    const lastColonIndex = value.lastIndexOf(":");

    if (lastColonIndex === -1 || lastColonIndex === value.length - 1) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Invalid format, expected IP:PORT",
      });
      return;
    }

    const ipPart = value.substring(0, lastColonIndex);
    const portPart = value.substring(lastColonIndex + 1);

    const ipValidationResult = z
      .string()
      .ip({
        message: `Invalid IP address.`,
      })
      .safeParse(ipPart);

    if (!ipValidationResult.success) {
      ipValidationResult.error.issues.forEach((issue) =>
        ctx.addIssue({
          ...issue,
          path: [...ctx.path, "ip"],
        }),
      );
    }

    const portSchema = z.coerce
      .number()
      .int({ message: "Invalid port." })
      .min(0, { message: "Port should be greater than or equal to 0." })
      .max(65535, { message: "The port must be less than or equal to 65535." });

    const portValidationResult = portSchema.safeParse(portPart);
    if (!portValidationResult.success) {
      portValidationResult.error.issues.forEach((issue) => {
        ctx.addIssue({
          ...issue,
          path: [...ctx.path, "port"],
        });
      });
    }
  });

export const listenerSchema = z.strictObject({
  listenerAddr: ipPortSchema,
  redirectAddr: ipPortSchema,
  agentId: z.coerce
    .number({ message: "invalid agent id" })
    .int({ message: "invalid agent id" }),
});

export type Listener = z.infer<typeof listenerSchema>;
