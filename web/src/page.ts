// The drop page: a small state machine over one card. Two modes, drop and
// reveal, selected by the path. The fragment is read once and removed from
// the address bar before any network request.

import * as b64 from "./base64.js";
import * as c from "./crypto.js";
import { parseDropFragment, parseRevealFragment, normalizeOrigin, type DropLink, type RevealLink } from "./link.js";
import { RelayClient, RelayError, type Status } from "./api.js";
import {
  DROP_COPY,
  REVEAL_COPY,
  dropStateFor,
  revealStateFor,
  formatCountdown,
  formatTime,
  describeRetention,
  relayErrorMessage,
  MAX_SECRET_BYTES,
  type DropState,
  type RevealState,
  type StateCopy,
} from "./state.js";

declare const __VERSION__: string;

const ICONS: Record<StateCopy["icon"], string> = {
  lock: '<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="10.5" width="16" height="10" rx="2.5"/><path d="M8 10.5V7.5a4 4 0 0 1 8 0v3"/><circle cx="12" cy="15.5" r="1.2"/></svg>',
  check: '<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="m8.5 12.5 2.5 2.5 4.5-5"/></svg>',
  clock: '<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M12 7.5V12l3 2"/></svg>',
  alert: '<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 4 3.5 19h17L12 4Z"/><path d="M12 10v4"/><circle cx="12" cy="16.5" r=".6" fill="currentColor"/></svg>',
  ban: '<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><circle cx="12" cy="12" r="9"/><path d="m6 6 12 12"/></svg>',
  key: '<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="8" cy="14" r="4"/><path d="m11 11 8.5-8.5M16 6l2.5 2.5M13.5 8.5 16 11"/></svg>',
  send: '<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M4 12 20 4l-4 16-4-7-8-1Z"/></svg>',
};

const EYE = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12Z"/><circle cx="12" cy="12" r="3"/></svg>';
const EYE_OFF = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M3 3l18 18M10.6 6.2A9.7 9.7 0 0 1 12 6c6 0 9.5 6 9.5 6a16 16 0 0 1-3.2 3.9M6.7 6.7C4 8.5 2.5 12 2.5 12s3.5 6.5 9.5 6.5a9 9 0 0 0 4.2-1M9.9 9.9a3 3 0 0 0 4.2 4.2"/></svg>';
const SUN = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><circle cx="12" cy="12" r="4"/><path d="M12 2.5v2M12 19.5v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2.5 12h2M19.5 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg>';
const MOON = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M20 14.5A8.5 8.5 0 0 1 9.5 4a8.5 8.5 0 1 0 10.5 10.5Z"/></svg>';

type Mode = "drop" | "reveal";

function el<T extends HTMLElement>(id: string): T {
  const e = document.getElementById(id);
  if (!e) {
    throw new Error(`missing element ${id}`);
  }
  return e as T;
}

class Page {
  private readonly main = el<HTMLElement>("main");
  private readonly icon = el<HTMLElement>("state-icon");
  private readonly title = el<HTMLHeadingElement>("state-title");
  private readonly text = el<HTMLParagraphElement>("state-text");
  private readonly next = el<HTMLParagraphElement>("state-next");
  private readonly status = el<HTMLDivElement>("status");
  private readonly context = el<HTMLElement>("context");
  private readonly form = el<HTMLFormElement>("drop-form");
  private readonly secret = el<HTMLTextAreaElement>("secret");
  private readonly sendButton = el<HTMLButtonElement>("send");
  private readonly toggleMask = el<HTMLButtonElement>("toggle-mask");
  private readonly maskNote = el<HTMLParagraphElement>("mask-note");
  private readonly revealPanel = el<HTMLDivElement>("reveal-panel");
  private readonly revealButton = el<HTMLButtonElement>("reveal");
  private readonly valuePanel = el<HTMLDivElement>("value-panel");
  private readonly value = el<HTMLTextAreaElement>("value");
  private readonly copyButton = el<HTMLButtonElement>("copy");
  private readonly toggleValue = el<HTMLButtonElement>("toggle-value");
  private readonly clearButton = el<HTMLButtonElement>("clear-clipboard");
  private readonly copyStatus = el<HTMLParagraphElement>("copy-status");
  private readonly expires = el<HTMLElement>("ctx-expires");

  private mode: Mode = "drop";
  private state: DropState | RevealState = "loading";
  private relay: RelayClient | null = null;
  private drop: DropLink | null = null;
  private reveal: RevealLink | null = null;
  private expiresAt: Date | null = null;
  private countdownTimer: number | undefined;
  private pollAbort: AbortController | null = null;
  private readonly maskSupported = typeof CSS !== "undefined" && CSS.supports("-webkit-text-security", "disc");

  constructor(private readonly href: string, private readonly pageOrigin: string, private readonly isExtension: boolean) {}

  async boot(): Promise<void> {
    this.wireTheme();
    this.wireForm();
    el<HTMLElement>("version").textContent = `burndrop ${__VERSION__}`;
    const hashIndex = this.href.indexOf("#");
    const frag = hashIndex >= 0 ? this.href.slice(hashIndex + 1) : "";
    // Remove the fragment before anything else so it never reaches history,
    // referrers, or extensions that read the URL later.
    history.replaceState(null, "", location.pathname + location.search);
    this.mode = detectMode(location.pathname, location.search);
    if (this.mode === "reveal") {
      this.setState("loading");
    }
    try {
      await c.ready();
      if (this.mode === "drop") {
        this.drop = parseDropFragment(frag);
      } else {
        this.reveal = parseRevealFragment(frag);
      }
    } catch (err) {
      this.fail("This link is incomplete or was altered. " + describeError(err));
      return;
    }
    const relayOrigin = (this.mode === "drop" ? this.drop!.relay : this.reveal!.relay) ?? this.pageOrigin;
    if (!this.isExtension && relayOrigin !== this.pageOrigin) {
      this.fail("This link points at a different relay than the one serving this page, which this page does not allow.");
      return;
    }
    try {
      this.relay = new RelayClient(normalizeOrigin(relayOrigin), `burndrop-page/${__VERSION__}`);
    } catch (err) {
      this.fail(describeError(err));
      return;
    }
    await this.fillContext();
    await this.loadStatus();
  }

  private async fillContext(): Promise<void> {
    if (this.mode === "drop") {
      const d = this.drop!;
      el("ctx-name").textContent = d.name;
      el("ctx-purpose").textContent = d.purpose || "(no reason given)";
      el("ctx-storage").textContent = d.storage || "(not stated)";
      el("ctx-retention").textContent = describeRetention(d.retention);
      el("ctx-fingerprint").textContent = await c.fingerprint(d.recipientKey);
      hide("ctx-opens-label", "ctx-opens", "ctx-copy-label", "ctx-copy");
    } else {
      const r = this.reveal!;
      el("ctx-name").textContent = r.name;
      el("ctx-copy").textContent = r.keepsCopy ? "yes" : "no";
      hide("ctx-purpose-label", "ctx-purpose", "ctx-storage-label", "ctx-storage", "ctx-retention-label", "ctx-retention", "ctx-fingerprint-label", "ctx-fingerprint", "ctx-fingerprint-help");
    }
    this.context.classList.remove("hidden-state");
  }

  private async loadStatus(): Promise<void> {
    const relay = this.relay!;
    let st: Status;
    try {
      st = this.mode === "drop" ? await relay.dropStatus(this.drop!.id) : await relay.revealStatus(this.reveal!.id);
    } catch (err) {
      if (err instanceof RelayError && err.status === 404) {
        this.setState("expired");
        return;
      }
      this.fail(err instanceof RelayError ? relayErrorMessage(err.code, err.detail) : describeError(err));
      return;
    }
    this.expiresAt = new Date(st.expires_at);
    this.startCountdown();
    if (this.mode === "drop") {
      const next = dropStateFor(st.state);
      this.setState(next);
      if (next === "sent") {
        void this.waitForDelivery();
      }
    } else {
      const next = revealStateFor(st.state);
      if (next === "opened") {
        REVEAL_COPY.opened.text = `It was opened ${formatTime(st.opened_at ?? "")}.`;
      }
      this.setState(next);
    }
  }

  private startCountdown(): void {
    const tick = (): void => {
      if (!this.expiresAt) return;
      const left = formatCountdown(this.expiresAt, new Date());
      this.expires.textContent = left === "expired" ? "expired" : `in ${left}`;
      if (left === "expired" && (this.state === "waiting" || this.state === "ready")) {
        this.setState("expired");
      }
    };
    tick();
    this.countdownTimer = window.setInterval(tick, 1000);
  }

  private wireTheme(): void {
    const button = el<HTMLButtonElement>("theme");
    const apply = (): void => {
      const dark = document.documentElement.classList.contains("dark");
      button.innerHTML = dark ? SUN : MOON;
      button.setAttribute("aria-label", dark ? "Switch to light theme" : "Switch to dark theme");
    };
    apply();
    button.addEventListener("click", () => {
      const dark = document.documentElement.classList.toggle("dark");
      try {
        localStorage.setItem("burndrop-theme", dark ? "dark" : "light");
      } catch {
        // Storage may be unavailable in private modes; the toggle still works for this page.
      }
      apply();
    });
  }

  private wireForm(): void {
    this.toggleMask.innerHTML = EYE;
    this.toggleMask.addEventListener("click", () => {
      const shown = this.secret.classList.toggle("masked") === false;
      this.toggleMask.setAttribute("aria-pressed", String(shown));
      this.toggleMask.setAttribute("aria-label", shown ? "Hide the secret" : "Show the secret");
      this.toggleMask.innerHTML = shown ? EYE_OFF : EYE;
    });
    if (!this.maskSupported) {
      this.maskNote.classList.remove("hidden-state");
    }
    this.form.addEventListener("submit", (ev) => {
      ev.preventDefault();
      void this.submit();
    });
    this.revealButton.addEventListener("click", () => {
      void this.doReveal();
    });
    this.toggleValue.addEventListener("click", () => {
      const shown = this.value.classList.toggle("masked") === false;
      this.toggleValue.textContent = shown ? "Hide" : "Show";
      this.toggleValue.setAttribute("aria-pressed", String(shown));
    });
    this.copyButton.addEventListener("click", () => {
      void this.copy(this.value.value, "Copied. Clear the clipboard when you are done.");
    });
    this.clearButton.addEventListener("click", () => {
      void this.copy("", "Clipboard cleared.");
    });
  }

  private async copy(text: string, ok: string): Promise<void> {
    try {
      await navigator.clipboard.writeText(text);
      this.copyStatus.textContent = ok;
    } catch {
      this.copyStatus.textContent = "Your browser blocked clipboard access. Select the text and copy it by hand.";
    }
  }

  private async submit(): Promise<void> {
    if (this.state !== "waiting" || !this.drop || !this.relay) {
      return;
    }
    const raw = this.secret.value;
    if (raw.trim() === "") {
      this.announce("Paste the secret first.");
      this.secret.focus();
      return;
    }
    const bytes = new TextEncoder().encode(raw);
    if (bytes.length > MAX_SECRET_BYTES) {
      this.announce(`The secret is too large (${bytes.length} bytes; the limit is ${MAX_SECRET_BYTES}).`);
      return;
    }
    this.setState("sending");
    try {
      const d = this.drop;
      const { format, secret } = c.secretFromBytes(bytes);
      const envelope: c.Envelope = { v: 1, type: "drop", name: d.name, format, secret, retention: d.retention, fingerprint: await c.fingerprint(d.recipientKey) };
      if (d.purpose) envelope.purpose = d.purpose;
      if (d.storage) envelope.storage = d.storage;
      const sealed = c.sealEnvelope(d.recipientKey, envelope);
      await this.relay.upload(d.id, d.uploadToken, await c.commitment(d.recipientKey), b64.encode(sealed));
      this.secret.value = "";
      this.setState("sent");
      void this.waitForDelivery();
    } catch (err) {
      if (err instanceof RelayError) {
        if (err.code === "already_uploaded" || (err.code === "gone" && err.state === "fetched")) {
          this.setState(err.state === "fetched" ? "delivered" : "sent");
          return;
        }
        if (err.code === "gone") {
          this.setState(err.state === "revoked" ? "revoked" : "expired");
          return;
        }
        this.setState("waiting");
        this.announce(relayErrorMessage(err.code, err.detail));
        return;
      }
      this.fail(describeError(err));
    }
  }

  /** waitForDelivery long polls until the agent fetches, so the page can say "delivered". */
  private async waitForDelivery(): Promise<void> {
    if (!this.relay || !this.drop) return;
    this.pollAbort?.abort();
    const abort = new AbortController();
    this.pollAbort = abort;
    for (let i = 0; i < 120 && !abort.signal.aborted; i++) {
      try {
        const st = await this.relay.dropStatus(this.drop.id, 30, "uploaded");
        if (st.state !== "uploaded") {
          if (!abort.signal.aborted) {
            this.setState(dropStateFor(st.state));
          }
          return;
        }
      } catch (err) {
        if (err instanceof RelayError && err.status === 404) {
          if (!abort.signal.aborted) this.setState("expired");
          return;
        }
        await sleep(3000);
      }
    }
  }

  private async doReveal(): Promise<void> {
    if (this.state !== "ready" || !this.reveal || !this.relay) {
      return;
    }
    this.setState("revealing");
    const r = this.reveal;
    let ciphertext: string;
    try {
      ({ ciphertext } = await this.relay.open(r.id, r.revealToken));
    } catch (err) {
      if (err instanceof RelayError && err.code === "gone") {
        if (err.state === "opened") {
          REVEAL_COPY.opened.text = `It was opened ${formatTime(err.at)}.`;
          this.setState("opened");
        } else {
          this.setState(err.state === "revoked" ? "revoked" : "expired");
        }
        return;
      }
      if (err instanceof RelayError && err.status === 404) {
        this.setState("expired");
        return;
      }
      this.setState("ready");
      this.announce(err instanceof RelayError ? relayErrorMessage(err.code, err.detail) : describeError(err));
      return;
    }
    try {
      const env = c.decryptEnvelope(r.key, b64.decode(ciphertext), c.revealAad(r.name, r.keepsCopy));
      if (env.type !== "reveal" || env.name !== r.name) {
        throw new c.EnvelopeError("the secret does not match this link");
      }
      const bytes = c.secretBytes(env);
      this.value.value = env.format === "text" ? env.secret : `base64:${b64.encode(bytes)}`;
      c.zero(r.key);
      this.setState("revealed");
      this.value.focus();
    } catch {
      this.fail("The secret could not be decrypted. The link was altered or the relay returned the wrong data. The relay copy is gone; ask your agent to send it again.");
    }
  }

  private setState(next: DropState | RevealState): void {
    this.state = next;
    const copy: StateCopy = this.mode === "drop" ? DROP_COPY[next as DropState] : REVEAL_COPY[next as RevealState];
    this.main.dataset["state"] = next;
    this.main.dataset["mode"] = this.mode;
    this.icon.innerHTML = ICONS[copy.icon];
    this.icon.className = `flex h-11 w-11 shrink-0 items-center justify-center rounded-xl ${iconTone(copy.icon)}`;
    this.title.textContent = copy.title;
    this.text.textContent = copy.text;
    this.next.textContent = copy.next;
    this.next.classList.toggle("hidden-state", copy.next === "");
    show(this.form, this.mode === "drop" && (next === "waiting" || next === "sending"));
    this.sendButton.disabled = next !== "waiting";
    this.secret.disabled = next !== "waiting";
    show(this.revealPanel, this.mode === "reveal" && (next === "ready" || next === "revealing"));
    this.revealButton.disabled = next !== "ready";
    show(this.valuePanel, next === "revealed");
    show(this.context, next !== "error" && next !== "loading");
    this.main.classList.remove("fade-in");
    void this.main.offsetWidth;
    this.main.classList.add("fade-in");
    this.announce(`${copy.title}. ${copy.text}`);
    if (next !== "loading" && next !== "waiting" && next !== "ready" && next !== "revealed") {
      this.title.focus();
    }
    if (next === "delivered" || next === "expired" || next === "revoked" || next === "error" || next === "opened" || next === "revealed") {
      this.pollAbort?.abort();
      if (this.countdownTimer !== undefined && next !== "revealed") {
        window.clearInterval(this.countdownTimer);
      }
    }
  }

  private fail(message: string): void {
    const copy = this.mode === "drop" ? DROP_COPY.error : REVEAL_COPY.error;
    copy.text = message;
    this.setState("error");
  }

  private announce(message: string): void {
    this.status.textContent = "";
    window.setTimeout(() => {
      this.status.textContent = message;
    }, 50);
  }
}

function iconTone(icon: StateCopy["icon"]): string {
  switch (icon) {
    case "check":
      return "bg-success-50 text-success-600 dark:bg-success-500/10 dark:text-success-500";
    case "alert":
    case "ban":
      return "bg-error-50 text-error-600 dark:bg-error-500/10 dark:text-error-500";
    case "clock":
      return "bg-warning-50 text-warning-600 dark:bg-warning-500/10 dark:text-warning-500";
    default:
      return "bg-brand-50 text-brand-500 dark:bg-brand-500/10";
  }
}

function show(node: HTMLElement, visible: boolean): void {
  node.classList.toggle("hidden-state", !visible);
}

function hide(...ids: string[]): void {
  for (const id of ids) {
    el(id).classList.add("hidden-state");
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => window.setTimeout(resolve, ms));
}

function describeError(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

export function detectMode(pathname: string, search: string): Mode {
  const path = pathname.replace(/\/$/, "");
  if (path.endsWith("/reveal")) return "reveal";
  if (path.endsWith("/drop")) return "drop";
  const mode = new URLSearchParams(search).get("mode");
  return mode === "reveal" ? "reveal" : "drop";
}

function applySavedTheme(): void {
  let saved: string | null = null;
  try {
    saved = localStorage.getItem("burndrop-theme");
  } catch {
    saved = null;
  }
  const dark = saved ? saved === "dark" : window.matchMedia("(prefers-color-scheme: dark)").matches;
  document.documentElement.classList.toggle("dark", dark);
}

applySavedTheme();
const isExtension = location.protocol === "chrome-extension:" || location.protocol === "moz-extension:";
// Inside the extension the page is served from the extension itself, so the
// relay is the origin the link came from (passed by the extension) unless
// the link names one with r.
const pageOrigin = isExtension ? (new URLSearchParams(location.search).get("origin") ?? "") : location.origin;
void new Page(location.href, pageOrigin, isExtension).boot();
