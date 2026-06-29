import { z } from "zod";

export const sessionSchema = z.strictObject({
  apiUrl: z.string(),
  authToken: z.string(),
});

export type Session = z.infer<typeof sessionSchema>;
