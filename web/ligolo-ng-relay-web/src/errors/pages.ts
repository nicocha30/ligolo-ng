import { HttpError } from "@/errors/index.tsx";

export class PageNotFoundError extends HttpError {
  public statusCode = 404;
  public name = "Page Not Found";
  public message = "This page could not be found.";
}
