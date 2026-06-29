import { z } from "zod";

export const authResponseSchema = z.strictObject({
  token: z.string(),
});

export type AuthResponse = z.infer<typeof authResponseSchema>;
