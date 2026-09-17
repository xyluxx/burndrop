// Relay API calls made by the page. Every call is a POST with the drop id
// in the body, so nothing sensitive reaches a URL or a log. The X-Client
// header is required by the relay; simple form posts cannot set it.

export const CLIENT_HEADER = "X-Client";

export class RelayError extends Error {
  constructor(
    public readonly status: number,
    public readonly code: string,
    public readonly detail: string = "",
    public readonly state: string = "",
    public readonly at: string = "",
  ) {
    super(`${code} (HTTP ${status})`);
  }
}

export interface Status {
  state: string;
  kind: string;
  created_at: string;
  expires_at: string;
  uploaded_at?: string;
  fetched_at?: string;
  opened_at?: string;
  revoked_at?: string;
}

export interface Fetcher {
  (input: string, init: RequestInit): Promise<Response>;
}

export class RelayClient {
  constructor(
    public readonly origin: string,
    private readonly clientName: string,
    private readonly fetchImpl: Fetcher = (input, init) => fetch(input, init),
  ) {}

  private async post<T>(path: string, body: unknown): Promise<T> {
    let res: Response;
    try {
      res = await this.fetchImpl(this.origin + path, {
        method: "POST",
        headers: { "Content-Type": "application/json", [CLIENT_HEADER]: this.clientName },
        body: JSON.stringify(body),
        credentials: "omit",
        cache: "no-store",
        referrerPolicy: "no-referrer",
      });
    } catch {
      throw new RelayError(0, "network");
    }
    let parsed: unknown = null;
    const text = await res.text();
    if (text) {
      try {
        parsed = JSON.parse(text);
      } catch {
        parsed = null;
      }
    }
    if (!res.ok) {
      const e = (parsed ?? {}) as Record<string, unknown>;
      throw new RelayError(res.status, typeof e["error"] === "string" ? e["error"] : `http_${res.status}`, str(e["detail"]), str(e["state"]), str(e["at"]));
    }
    if (parsed === null || typeof parsed !== "object") {
      throw new RelayError(res.status, "malformed_response");
    }
    return parsed as T;
  }

  dropStatus(id: string, waitSeconds = 0, waitWhile = ""): Promise<Status> {
    return this.post<Status>("/api/v1/drops/status", { drop_id: id, wait_seconds: waitSeconds, wait_while: waitWhile });
  }

  revealStatus(id: string, waitSeconds = 0, waitWhile = ""): Promise<Status> {
    return this.post<Status>("/api/v1/reveals/status", { drop_id: id, wait_seconds: waitSeconds, wait_while: waitWhile });
  }

  upload(id: string, uploadToken: string, commitment: string, ciphertext: string): Promise<{ state: string }> {
    return this.post("/api/v1/drops/upload", { drop_id: id, upload_token: uploadToken, commitment, ciphertext });
  }

  open(id: string, revealToken: string): Promise<{ ciphertext: string; created_at: string }> {
    return this.post("/api/v1/reveals/open", { drop_id: id, reveal_token: revealToken });
  }
}

function str(v: unknown): string {
  return typeof v === "string" ? v : "";
}
