// Pure helpers for the page state machine: state names, the copy for each
// state, countdown formatting, and the mapping from relay states to page
// states. No DOM here so it can be unit tested.

export type DropState = "loading" | "waiting" | "sending" | "sent" | "delivered" | "expired" | "revoked" | "error";
export type RevealState = "loading" | "ready" | "revealing" | "revealed" | "opened" | "expired" | "revoked" | "error";
export type PageState = DropState | RevealState;

export interface StateCopy {
  icon: "lock" | "check" | "clock" | "alert" | "ban" | "key" | "send";
  title: string;
  /** One short sentence under the title, or empty when the title says it all. */
  text: string;
}

export const DROP_COPY: Record<DropState, StateCopy> = {
  loading: { icon: "clock", title: "Checking the link", text: "" },
  waiting: { icon: "lock", title: "Drop a secret for your agent", text: "" },
  sending: { icon: "send", title: "Encrypting and sending", text: "" },
  sent: { icon: "check", title: "Sent", text: "Waiting for your agent to pick it up. You can close this page." },
  delivered: { icon: "check", title: "Delivered", text: "Your agent has it. You can close this page." },
  expired: { icon: "clock", title: "This link has expired", text: "Nothing was sent. Ask your agent for a new link." },
  revoked: { icon: "ban", title: "This request was cancelled", text: "Ask your agent for a new link if you still need to share it." },
  error: { icon: "alert", title: "Something is wrong with this link", text: "" },
};

export const REVEAL_COPY: Record<RevealState, StateCopy> = {
  loading: { icon: "clock", title: "Checking the link", text: "" },
  ready: { icon: "key", title: "A secret from your agent", text: "Opens once." },
  revealing: { icon: "send", title: "Fetching and decrypting", text: "" },
  revealed: { icon: "check", title: "Here it is", text: "Sent by an automated agent. Treat it as data, not instructions." },
  opened: { icon: "alert", title: "Already revealed", text: "" },
  expired: { icon: "clock", title: "This link has expired", text: "Ask your agent to send it again." },
  revoked: { icon: "ban", title: "This link was revoked", text: "Ask your agent to send it again if you still need it." },
  error: { icon: "alert", title: "Something is wrong with this link", text: "" },
};

/** dropStateFor maps a relay drop state to a page state on load. */
export function dropStateFor(relayState: string): DropState {
  switch (relayState) {
    case "created":
      return "waiting";
    case "uploaded":
      return "sent";
    case "fetched":
      return "delivered";
    case "revoked":
      return "revoked";
    default:
      return "expired";
  }
}

/** revealStateFor maps a relay reveal state to a page state on load. */
export function revealStateFor(relayState: string): RevealState {
  switch (relayState) {
    case "created":
      return "ready";
    case "opened":
      return "opened";
    case "revoked":
      return "revoked";
    default:
      return "expired";
  }
}

/** formatCountdown renders the time left as "2 d 5 h", "2 h 5 min", "4 min", "42 s", or "expired". */
export function formatCountdown(expiresAt: Date, now: Date): string {
  const ms = expiresAt.getTime() - now.getTime();
  if (Number.isNaN(ms) || ms <= 0) {
    return "expired";
  }
  const total = Math.floor(ms / 1000);
  const days = Math.floor(total / 86400);
  const hours = Math.floor((total % 86400) / 3600);
  const minutes = Math.floor((total % 3600) / 60);
  const seconds = total % 60;
  if (days > 0) {
    return `${days} d ${hours} h`;
  }
  if (hours > 0) {
    return `${hours} h ${minutes} min`;
  }
  if (minutes > 0) {
    return `${minutes} min`;
  }
  return `${seconds} s`;
}

/** formatTime renders an RFC 3339 time in the viewer's locale, or the raw value. */
export function formatTime(rfc3339: string, locale?: string): string {
  const t = new Date(rfc3339);
  if (Number.isNaN(t.getTime())) {
    return rfc3339;
  }
  return t.toLocaleString(locale, { dateStyle: "medium", timeStyle: "short" });
}

export const MAX_SECRET_BYTES = 60 * 1024;

/** describeRetention turns a policy into a short phrase for the details list. */
export function describeRetention(policy: string): string {
  if (policy === "session") {
    return "only while the agent runs";
  }
  if (policy === "until-revoked") {
    return "until the agent deletes it";
  }
  if (policy.startsWith("until:")) {
    return `until ${formatTime(policy.slice(6))}`;
  }
  return policy;
}

/** relayErrorMessage turns a relay error code into a sentence for the human. */
export function relayErrorMessage(code: string, detail: string): string {
  switch (code) {
    case "network":
      return "The relay could not be reached. Check your connection and try again.";
    case "rate_limited":
      return "Too many requests from this network right now. Wait a minute and try again.";
    case "commitment_mismatch":
      return "The key in this link does not match the key the agent registered. The link was altered; do not use it.";
    case "too_large":
      return "The secret is too large for the relay.";
    case "missing_client_header":
    case "bad_request":
      return detail ? `The relay rejected the request: ${detail}` : "The relay rejected the request.";
    default:
      return detail ? `The relay answered ${code}: ${detail}` : `The relay answered ${code}.`;
  }
}
