import { z } from "zod";
import { ValidationError } from "@/errors/validation.ts";

export const validate = <S extends z.Schema>(
  data: unknown,
  schema: S,
): z.infer<S> => {
  try {
    return schema.parse(data);
  } catch (err) {
    throw new ValidationError(err);
  }
};
