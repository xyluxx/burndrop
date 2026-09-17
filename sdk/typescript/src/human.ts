/**
 * The human side of both flows without a browser: exactly what the drop
 * page does, with the same envelope and the same checks. Useful for tests,
 * scripts, and command line tools. Mirrors cmd/burndrop/cmd_human.go.
 */
import {
  commitment,
  decryptEnvelope,
  fingerprint,
  revealAad,
  sealEnvelope,
  secretBytes,
  secretField,
  zero,
  type Envelope,
  type SecretFormat,
} from "./crypto.js";
import { BurndropError, RelayError, ValidationError, isRelayCode } from "./errors.js";
import { parseDropLink, parseRevealLink, relayOrigin } from "./link.js";
import { RelayClient, RelayCode, SlotState, type RelayClientOptions } from "./relay.js";

export interface HumanOptions extends RelayClientOptions {
  /** Talk to this relay instead of the one named by the link. */
  relay?: string;
  /** Abort signal for the relay calls. */
  signal?: AbortSignal;
}

export interface SubmitResult {
  name: string;
  purpose: string;
  storage: string;
  retention: string;
  /** Fingerprint of the key the value was encrypted to; compare it with the agent's message. */
  fingerprint: string;
  sizeBytes: number;
  relay: string;
}

export interface OpenResult {
  name: string;
  value: Uint8Array;
  format: SecretFormat;
  keepsCopy: boolean;
  relay: string;
}

const utf8 = new TextEncoder();

function makeClient(origin: string, options: HumanOptions): RelayClient {
  const clientOptions: RelayClientOptions = {};
  if (options.clientName !== undefined) {
    clientOptions.clientName = options.clientName;
  }
  if (options.fetch !== undefined) {
    clientOptions.fetch = options.fetch;
  }
  if (options.timeoutMs !== undefined) {
    clientOptions.timeoutMs = options.timeoutMs;
  }
  return new RelayClient(origin, "", clientOptions);
}

/**
 * Submits a value for a drop link: checks that the link is still open,
 * builds the envelope from the link's display fields and the fingerprint
 * of its key, seals it to that key, and uploads it with the key's
 * commitment. The relay refuses the upload when the commitment differs
 * from the one the agent registered, which is how an altered link is
 * caught; that refusal surfaces here as a BurndropError.
 */
export async function submit(link: string, value: Uint8Array | string, options: HumanOptions = {}): Promise<SubmitResult> {
  const { drop, pageOrigin } = parseDropLink(link);
  const relay = options.relay ?? relayOrigin(drop, pageOrigin);
  const client = makeClient(relay, options);
  const bytes = typeof value === "string" ? utf8.encode(value) : value;
  if (bytes.length === 0) {
    throw new ValidationError("empty value");
  }
  let status;
  try {
    status = await client.dropStatus(drop.id, 0, "", options.signal);
  } catch (err) {
    if (isRelayCode(err, RelayCode.NotFound)) {
      throw new BurndropError("this link has expired or was never created", { cause: err });
    }
    throw err;
  }
  if (status.state !== SlotState.Created) {
    throw new BurndropError("this link can no longer be used (state: " + status.state + ")");
  }
  const fp = await fingerprint(drop.recipientKey);
  const env: Envelope = {
    v: 1,
    type: "drop",
    name: drop.name,
    purpose: drop.purpose,
    storage: drop.storage,
    retention: drop.retention,
    fingerprint: fp,
    ...secretField(bytes),
  };
  const sealed = await sealEnvelope(drop.recipientKey, env);
  try {
    await client.upload(drop.id, drop.uploadToken, await commitment(drop.recipientKey), sealed, options.signal);
  } catch (err) {
    if (isRelayCode(err, RelayCode.CommitmentMismatch)) {
      throw new BurndropError("the key in this link does not match the key the agent registered; the link was altered, do not use it", { cause: err });
    }
    throw err;
  }
  return {
    name: drop.name,
    purpose: drop.purpose,
    storage: drop.storage,
    retention: drop.retention,
    fingerprint: fp,
    sizeBytes: bytes.length,
    relay,
  };
}

/**
 * Opens a reveal link: checks that it is still unopened, downloads the
 * ciphertext (which deletes it from the relay), and decrypts it with the
 * link's key and the display fields as additional data. A link whose
 * display fields were altered fails to decrypt.
 */
export async function open(link: string, options: HumanOptions = {}): Promise<OpenResult> {
  const { reveal, pageOrigin } = parseRevealLink(link);
  const relay = options.relay ?? relayOrigin(reveal, pageOrigin);
  const client = makeClient(relay, options);
  let status;
  try {
    status = await client.revealStatus(reveal.id, 0, "", options.signal);
  } catch (err) {
    if (isRelayCode(err, RelayCode.NotFound)) {
      throw new BurndropError("this link has expired or was never created", { cause: err });
    }
    throw err;
  }
  if (status.state !== SlotState.Created) {
    throw new BurndropError("this link was already used or revoked (state: " + status.state + ")");
  }
  const { ciphertext } = await client.open(reveal.id, reveal.revealToken, options.signal);
  let env: Envelope;
  try {
    env = await decryptEnvelope(reveal.key, ciphertext, revealAad(reveal.name, reveal.keepsCopy));
  } catch (err) {
    if (err instanceof RelayError) {
      throw err;
    }
    throw new BurndropError(
      "the secret could not be decrypted: the link was altered or the relay returned the wrong data; the relay copy is gone, ask the agent to send it again",
      { cause: err },
    );
  } finally {
    zero(reveal.key);
  }
  return { name: env.name, value: secretBytes(env), format: env.format, keepsCopy: reveal.keepsCopy, relay };
}
