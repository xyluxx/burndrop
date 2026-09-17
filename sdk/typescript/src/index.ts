/**
 * burndrop: one-time, end-to-end encrypted secret exchange between humans
 * and AI agents through a zero-knowledge relay.
 *
 * Subpath imports are available for the browser-safe pieces:
 * "burndrop/crypto" and "burndrop/link" have no Node-only imports.
 * "burndrop/relay", "burndrop/agent", and "burndrop/human" are the relay
 * client, the agent flows, and the human side of the flows.
 */
export * from "./errors.js";
export * from "./crypto.js";
export * from "./link.js";
export * from "./relay.js";
export * from "./redact.js";
export * from "./run.js";
export * from "./agent.js";
export * as human from "./human.js";
export { submit as submitDrop, open as openReveal, type HumanOptions, type SubmitResult, type OpenResult } from "./human.js";
export { VERSION, DEFAULT_CLIENT_NAME } from "./version.js";
