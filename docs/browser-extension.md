# Browser extension

The burndrop browser extension (`extension/`) is a Manifest V3 extension for
Chrome and Firefox, built from one source. It carries its own copy of the drop
page and opens drop and reveal links in that copy, so the page a relay serves
never runs for the relays you have told it about. It is optional: the hosted
page is the default experience and stays fully functional without it.

## What it protects against

The protocol keeps the relay out of the plaintext: the page encrypts in the
browser, the relay stores ciphertext, and the keys travel in the URL fragment,
which browsers never send to servers. The remaining trust in the hosted flow
is in the page itself. Whoever controls the host that serves `/drop` and
`/reveal` (the relay operator, their hosting provider, a CDN, or an attacker
who got into any of them) can serve a page that looks identical and posts the
secret, or the decrypted value, somewhere else. A person can catch this by
checking the page hash against the release (see the release verification
document), but nobody does that on every link.

The extension turns that manual check into a property of the browser. For a
relay you add on its options page, the page that handles a link is the one
packaged in the extension, whose hash you checked once when you installed it.
A modified hosted page cannot run, because the tab leaves it before any of
its code executes. The relay still sees exactly what it saw before:
ciphertext, drop IDs, tokens, and timing.

What it does not do:

- It does not protect against a compromised browser, a malicious extension
  with broad permissions, or a compromised machine.
- It only acts on origins you added. A link to a lookalike domain opens the
  hosted page of that domain as usual. Verify mode (below) helps you check a
  relay before you trust it.
- It does not change what the link itself guarantees. The bundled page runs
  the same checks as the hosted one: fingerprint display, authenticated
  metadata, one-time reveal.

## How it works

1. **Adding a relay.** On the options page you enter the origin your agent's
   links point at, for example `https://relay.example`. The browser asks you
   to grant the extension access to that site. The origin is stored in
   `chrome.storage.local`, and the background registers a content script for
   `<origin>/drop*` and `<origin>/reveal*` that runs at `document_start`, with
   `persistAcrossSessions` so it survives browser restarts. At install, update,
   and browser start the background rebuilds the registrations from storage,
   and the options page asks it to do the same after every change, so a
   registration never outlives its origin.
2. **Opening a link.** The content script runs before the hosted document can
   execute anything. If the path is `/drop` or `/reveal` it reads
   `location.origin`, the path, and `location.hash` (content scripts share the
   page's window, so the fragment is readable), calls `window.stop()` so the
   hosted document stops parsing, and sends the three values to the
   background.
3. **Moving the tab.** The background checks that the origin is one you added
   and navigates the tab with `tabs.update` to
   `page.html?mode=<drop|reveal>&origin=<encoded origin>#<the original
   fragment>`. An empty fragment still moves the tab; the bundled page then
   shows its "link is incomplete" state, as the hosted page would.
4. **The bundled page.** `page.html`, `page.js`, and `page.css` are the files
   `web/build.mjs` writes to `web/build/ext/`: the same page as the hosted
   single file, split in three because Manifest V3 forbids inline script. The
   page removes the fragment with `history.replaceState` before its first
   request, takes the relay from the `origin` parameter, or from the link's
   `r` field when present, and talks to it exactly as the hosted page would.
5. **Removing a relay.** The registration is unregistered and the host
   permission released.

If the links your agent produces carry an `r` field (a split deployment where
a static host serves the page and the relay lives elsewhere), add the origin
the links point at; the bundled page uses `r` for the API.

## Installing

Every release ships `burndrop-extension-chrome.zip`,
`burndrop-extension-firefox.zip`, and a `.sha256` file next to each. Check
the hash before unpacking:

```sh
sha256sum -c burndrop-extension-chrome.zip.sha256
```

On Windows, compare `Get-FileHash burndrop-extension-chrome.zip` with the
`.sha256` file. The zips are reproducible, so anyone can rebuild them from
the tagged source and compare (see Build and test).

**Chrome, Chromium, Edge, Brave (development install):** unzip the Chrome
package, open `chrome://extensions`, enable Developer mode, choose *Load
unpacked*, and select the unzipped folder.

**Firefox (temporary add-on):** open `about:debugging#/runtime/this-firefox`,
choose *Load Temporary Add-on*, and select the Firefox zip or its unzipped
`manifest.json`. Firefox removes temporary add-ons when it closes; a
permanent install needs the package signed by Mozilla Add-ons.

Store listings on the Chrome Web Store and Mozilla Add-ons are future work
and an owner action. Before the first Mozilla submission the placeholder
add-on ID `burndrop-extension@burndrop.example` in `extension/build.mjs` must
be replaced with the permanent one; the ID cannot change afterwards.

## Using it

Open the options page from the toolbar button or from the extension's
details page. Add the origin of each relay whose links you open (scheme and
host only, `https://`; `http://localhost` and `http://127.0.0.1` are accepted
for development). The browser shows a permission prompt for that site.

From then on a drop or reveal link from that relay opens as
`chrome-extension://<id>/page.html?mode=...&origin=...` (Firefox:
`moz-extension://<uuid>/...`) with the fragment already removed from the
address bar. The footer shows the extension version and the version and hash
of the bundled page.

## Permissions

| Permission | Why |
| --- | --- |
| `storage` | The list of relay origins you added. Nothing else is stored. |
| `scripting` | `scripting.registerContentScripts` registers the content script for each relay at runtime; static `content_scripts` cannot express hosts chosen later. |
| `optional_host_permissions`: `https://*/*`, `http://localhost/*`, `http://127.0.0.1/*` | Declares which hosts the extension may ask for. Nothing is granted at install; each relay's permission (`<origin>/*`) is requested when you add or verify it. The permission does three things for that origin only: it lets the content script run there, it lets the bundled page call the relay's API from the extension's origin (browsers exempt extension pages from CORS only on hosts they hold a permission for), and it lets verify mode fetch the page. |

Not requested: `tabs` (updating the tab a message came from needs no
permission, and the extension never reads tab URLs or titles),
`declarativeNetRequest` and `webRequest` (no traffic is inspected or
modified), and `<all_urls>`. The toolbar button only opens the options page.
The Firefox manifest declares `data_collection_permissions: { required:
["none"] }`: the extension collects and transmits nothing.

Extension pages run under
`script-src 'self' 'wasm-unsafe-eval'; object-src 'self'` plus
`default-src 'self'`, `style-src 'self'`, `img-src 'self' data:`,
`font-src 'self' data:`, `connect-src 'self' https: http://localhost:*
http://127.0.0.1:*`, `frame-ancestors 'none'`, `form-action 'none'`, and
`base-uri 'none'`. `'wasm-unsafe-eval'` is what libsodium's WebAssembly
needs; it permits WebAssembly compilation, not script evaluation. No remote
code, no `eval`.

## Verify mode

The options page can check any relay, added or not. Enter its origin and
choose *Verify*. After the permission prompt the extension fetches
`<origin>/drop` with `cache: "no-store"`, hashes the response body with
SHA-256, and compares it with the hash of the page bundled in the extension.
It also asks the relay for its own claim, the `page_sha256` and
`page_version` fields of `GET <origin>/api/v1/info`. The result is one of:

- **Verified (page version X):** the page served right now is byte for byte
  the bundled page.
- **Mismatch:** the served page differs; both hashes are shown. A mismatch is
  also what a relay running a different release (older or newer than the
  extension) produces, so compare the served hash with the hashes in the
  release notes before concluding the page was tampered with.
- **Could not fetch:** the relay did not answer or answered with an error.

Below the verdict the relay's claim is shown with whether it agrees with what
was actually served. A relay that claims the genuine hash while serving
something else is the case verify mode exists for.

Verify mode borrows the host permission; if the origin is not one of your
protected relays the permission is released again when the check finishes.

## What the relay must support

Requests from extension pages carry `Origin: chrome-extension://<id>` or
`Origin: moz-extension://<uuid>`. The burndrop relay accepts these origins on
its API in addition to its configured page origins, because they are the
extension's own copy of the page and the allowlist is not an authentication
boundary (the relay already serves clients that send no `Origin` at all).
A reverse proxy in front of the relay must not strip or reject them.

## Limitations and deviations from the design

- **No `web_accessible_resources`.** The design listed `page.html` under
  `web_accessible_resources` for the configured hosts as a fallback for direct
  navigation. Manifest V3 declares that list statically, while hosts are
  chosen at runtime, and exposing `page.html` to every web origin would let
  any site open it and probe it. The content script path is the only way in;
  a web page cannot navigate to the extension's page directly.
- **Static `connect-src`.** The design wanted `connect-src` limited to the
  configured origins. The extension CSP is fixed at build time, so it allows
  `https:` (plus localhost for development) and relies on the per-origin host
  permission as the dynamic gate.
- **Verify mode compares against one release.** The design described a
  bundled manifest of known versions with a separate "unknown version" result.
  The extension bundles the hash of the page it was built with; a page from
  another release shows as a mismatch with both hashes, and the release notes
  are the place to look them up.
- **Firefox ignores ports.** Firefox match patterns cannot carry a port
  (Firefox bug 1362809) and ignore the URL's port when matching, so on
  Firefox a relay you add covers every port of that host. The tab is still
  moved with the actual origin, so the page talks to the right relay. Chrome
  patterns are exact.
- **Firefox is built, not driven by the test suite.** Playwright loads
  extensions only into Chromium, so the end-to-end suite runs the Chrome
  build. The Firefox build comes from the same source and manifest generator
  (`background.scripts` instead of `background.service_worker`, plus the
  `browser_specific_settings.gecko` block) and needs a manual pass as a
  temporary add-on. `strict_min_version` is 140.0, the first Firefox that
  understands the data collection consent key.
- **Trimmed `page.meta.json`.** The package carries only the `version` and
  `sha256` fields of the page build's metadata, because the build timestamp
  in the original would make two otherwise identical packages differ.
- **`declarativeNetRequest` is not used**, as the design said: whether its
  matcher sees fragments is undocumented, and the content script path is
  observable in the tests.
- **A stale registration fails open.** If a registration ever outlives its
  origin in storage (storage and registrations are kept in step, so this is
  a recovery path), the background removes it and the content script reloads
  the tab, which then shows the hosted page as if the extension were not
  installed.
- **Branded Chrome no longer side-loads extensions from the command line**
  (the `--load-extension` switch was removed in Chrome 137), which is why the
  suite runs Playwright's Chromium build.

## Build and test

The extension bundles the page from `web/build/ext/`, so build the page
first. Every dependency is a development dependency pinned to an exact
version; the extension itself has no runtime dependencies.

```sh
cd web && npm install && node build.mjs
cd ../extension && npm install
npm run typecheck
npm run build                     # dist/chrome, dist/firefox, zips, .sha256 files
node build.mjs --version 1.2.3    # release version; Chrome requires numeric versions
npm run icons                     # regenerate icons/*.png
```

`node build.mjs --test` (or `BURNDROP_EXTENSION_TEST=1`) produces
`dist/chrome-test` and `dist/firefox-test`, which additionally declare
`http://localhost/*` and `http://127.0.0.1/*` as required host permissions so
the test suite never meets a permission prompt. Test builds are never zipped.
The release build does not contain that grant.

The zips are reproducible: entries are stored uncompressed, sorted by name,
with one fixed timestamp and no extra fields, so a build from the same
sources yields the same bytes and the same `.sha256`. The page inside them is
whatever `web/build.mjs` produced, so a full rebuild starts there.

Tests:

```sh
npm run test:unit                 # origin validation and the zip writer (vitest)
node ../web/e2e/build-relay.mjs   # the relay with the page embedded; needs Go on PATH
npm run test:e2e                  # node build.mjs --test && playwright test
npm test                          # all of the above
```

The end-to-end suite loads `dist/chrome-test` into a persistent headless
Chromium context (Playwright's `chromium` channel; install it once with
`npx playwright install chromium`) and starts the real relay on port 8941
(`BURNDROP_EXTENSION_E2E_PORT` overrides it) so it can run alongside the web
suite. It covers: adding and removing a relay on the options page and the
resulting content script registration; a drop link moving to the bundled
page with its fragment intact, the secret being decrypted by the agent side,
and every API call carrying the extension's origin; a reveal link; a link
without a fragment; a bait relay whose page reports the moment any of its
scripts run, which never happens; verify mode against the running relay
(verified), an impostor that claims the genuine hash while serving its own
page (mismatch), and a closed port (could not fetch); and a browser restart
after which the registrations are rebuilt from storage.
