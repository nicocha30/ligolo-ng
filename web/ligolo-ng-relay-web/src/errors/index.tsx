import { addToast } from "@heroui/react";

export abstract class AppError extends Error {
  static fromError(errorData: Error | unknown) {
    const error = new UnknownAppError();
    if (errorData instanceof Error) {
      error.name = errorData.name;
      error.stack = errorData.stack;
      error.message = errorData.message;
    }

    return error;
  }

  public toast() {
    return addToast({
      severity: "danger",
      color: "danger",
      title: `Error: ${this.name}`,
      description: this.message
    });
  }
}

export abstract class HttpError extends AppError {
  public statusCode: number = 500;

  static fromError(errorData: Error | unknown, statusCode = 500) {
    const error = new UnknownHttpError();
    error.statusCode = statusCode;

    if (errorData instanceof Error) {
      error.name = errorData.name;
      error.stack = errorData.stack;
      error.message = errorData.message;
    }

    return error;
  }

  public toast() {
    return addToast({
      severity: "danger",
      color: "danger",
      title: `(${this.statusCode}) Error: ${this.name}`,
      description: this.message
    });
  }
}

export class UnknownAppError extends AppError {
  public name = "Unknown Error";
  public message = "Something unexpected happened";
}

export class UnknownHttpError extends HttpError {
  public name = "Unknown API Error";
  public message = "API responded with an unexpected error";

  static fromResponse(response: Awaited<ReturnType<Response["json"]>>) {
    const apiError = new UnknownHttpError();
    apiError.statusCode = response.status ?? 500;
    apiError.name = response.error;
    apiError.message = "";

    return apiError;
  }
}
