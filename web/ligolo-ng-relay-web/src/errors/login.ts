import { AppError } from "@/errors/index.tsx";

export class SessionExpiredError extends AppError {
  public statusCode = 401;
  public message = "You have been logged out";
  public name  = "Session Expired";
}

export class AccessDeniedError extends AppError {
  public statusCode = 401;
  public message  = "You must be registed to access this ressource";
  public name = "Access Denied";
}

export class InvalidApiUrlError extends AppError {
  public statusCode = 402;
  public name = "Invalid API URL";
}


export class SessionParseFailedError extends AppError {
  public name = "Unable to parse session data";

  constructor(message: string) {
    super();
    this.message = message;
  }
}
