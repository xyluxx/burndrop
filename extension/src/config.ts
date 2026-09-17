// The extension's only persistent state: the relay origins the human added,
// kept in chrome.storage.local.

const KEY = "origins";

export async function loadOrigins(): Promise<string[]> {
  const stored = await chrome.storage.local.get(KEY);
  const value: unknown = stored[KEY];
  return Array.isArray(value) ? value.filter((v): v is string => typeof v === "string") : [];
}

export async function saveOrigins(origins: string[]): Promise<void> {
  await chrome.storage.local.set({ [KEY]: origins });
}

export function onOriginsChanged(listener: () => void): void {
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area === "local" && KEY in changes) {
      listener();
    }
  });
}
