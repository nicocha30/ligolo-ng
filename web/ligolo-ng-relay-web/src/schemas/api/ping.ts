import { z } from "zod";

export const pingResponseSchema = z.strictObject({
  message: z.string(),
});

export type PingResponse = z.infer<typeof pingResponseSchema>;
