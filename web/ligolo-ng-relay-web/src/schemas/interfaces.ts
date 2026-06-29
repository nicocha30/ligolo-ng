import { z } from "zod";

export const interfaceRouteSchema = z.strictObject({
  interface: z.string().nonempty(),
  routes: z.string().cidr().array(),
});

export const interfaceSchema = z.strictObject({
  interface: z.string().nonempty(),
});

export type Interface = z.infer<typeof interfaceSchema>;
