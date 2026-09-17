/**
 * Error types. Every error thrown by this package extends BurndropError so a
 * caller can catch the family with one instanceof check and then narrow.
 *
 * The Go implementation uses sentinel errors (ErrDecrypt, ErrPadding,
 * ErrEnvelope, ErrLink, ...); the classes here carry the same distinctions
 * as a `code` property where one class covers several sentinels.
 */

/** Base class for every error raised by the burndrop package. */
export class BurndropError extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = "BurndropError";
  }
}

/** Malformed base64url input (padding, alphabet, or non-canonical bits). */
export class EncodingError extends BurndropError {
  constructor(message: string) {
    super(message);
    this.name = "EncodingError";
  }
}

/** Codes for CryptoError, matching the Go sentinel errors. */
export type CryptoErrorCode = "decrypt" | "padding" | "size" | "length";

/**
 * A cryptographic operation failed. The "decrypt" code is deliberately the
 * same for a wrong key, altered ciphertext, or altered additional data.
 */
export class CryptoError extends BurndropError {
  readonly code: CryptoErrorCode;

  constructor(code: CryptoErrorCode, message: string) {
    super(message);
    this.name = "CryptoError";
    this.code = code;
  }
}

/** The envelope JSON is malformed or fails validation. */
export class EnvelopeError extends BurndropError {
  constructor(message: string) {
    super("invalid envelope: " + message);
    this.name = "EnvelopeError";
  }
}

/** A link or origin is malformed. */
export class LinkError extends BurndropError {
  constructor(message: string) {
    super("invalid link: " + message);
    this.name = "LinkError";
  }
}

/** The relay could not be reached or returned something unreadable. */
export class RelayUnavailableError extends BurndropError {
  constructor(message: string, options?: { cause?: unknown }) {
    super("relay: " + message, options);
    this.name = "RelayUnavailableError";
  }
}

/** The relay answered with an error response. */
export class RelayError extends BurndropError {
  /** HTTP status code. */
  readonly status: number;
  /** Error code from the body, for example "gone" or "bad_token". */
  readonly code: string;
  /** Human readable detail when the relay gives one. */
  readonly detail: string;
  /** Slot state when the error is about state, for example "fetched". */
  readonly state: string;
  /** When the state was entered, when the relay reports it. */
  readonly at: Date | undefined;

  constructor(status: number, code: string, detail = "", state = "", at?: Date) {
    let message = "relay: " + code;
    if (state !== "") {
      message += " (" + state + ")";
    }
    if (detail !== "") {
      message += ": " + detail;
    }
    message += " [HTTP " + String(status) + "]";
    super(message);
    this.name = "RelayError";
    this.status = status;
    this.code = code;
    this.detail = detail;
    this.state = state;
    this.at = at;
  }
}

/** An argument given to the agent or human helpers is not acceptable. */
export class ValidationError extends BurndropError {
  constructor(message: string) {
    super(message);
    this.name = "ValidationError";
  }
}

/** Reports whether err is a RelayError with the given code. */
export function isRelayCode(err: unknown, code: string): boolean {
  return err instanceof RelayError && err.code === code;
}
