import { AppError } from "@/errors/index.tsx";
import { ZodError } from "zod";
export class ValidationError extends AppError {
  public name = "Invalid Data";
  public zodError: unknown;

  constructor(zodError: unknown) {
    super();

    if (zodError instanceof ZodError) {
      this.stack = zodError.stack;
      this.zodError = zodError;
      console.error(zodError);
      // TODO parse zod response
    }
  }
}
