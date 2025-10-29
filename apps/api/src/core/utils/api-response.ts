import type { Context } from "hono";
import type {
  ContentfulStatusCode,
  ContentlessStatusCode,
} from "hono/utils/http-status";

interface SuccessResponse {
  status: "success";
  data: unknown;
}

interface FailureResponse {
  status: "failure";
  data: unknown;
}

interface ErrorResponse {
  status: "error";
  message: string;
}

export class ApiResponse {
  /**
   * @description Creates a success response.
   * @param c - The context.
   * @param status - The status code.
   * @param data - The success data.
   * @returns The response.
   */
  static success(
    c: Context,
    {
      status,
      data,
    }: {
      status: ContentfulStatusCode;
      data: unknown;
    },
  ) {
    // Create the data.
    const response: SuccessResponse = {
      status: "success",
      data,
    };

    return c.json(response, status);
  }

  /**
   * @description Creates a failure response.
   * @param c - The context.
   * @param status - The status code.
   * @param data - The failure data (eg. errors).
   * @returns The response.
   */
  static failure(
    c: Context,
    {
      status,
      data,
    }: {
      status: ContentfulStatusCode;
      data: unknown;
    },
  ) {
    // Create the data.
    const response: FailureResponse = {
      status: "failure",
      data,
    };

    return c.json(response, status);
  }

  /**
   * @description Creates an error response.
   * @param c - The context.
   * @param status - The status code.
   * @param message - The message that describes the error.
   * @returns The response.
   */
  static error(
    c: Context,
    {
      status,
      message,
    }: {
      status: ContentfulStatusCode;
      message: string;
    },
  ) {
    // Create the data.
    const response: ErrorResponse = {
      status: "error",
      message,
    };

    return c.json(response, status);
  }

  /**
   * @description Creates an empty response.
   * @param c - The context.
   * @param status - The status code.
   * @returns The response.
   */
  static empty(c: Context, status: ContentlessStatusCode) {
    return c.newResponse(null, status);
  }
}
