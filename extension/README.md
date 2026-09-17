# burndrop browser extension

Manifest V3 extension for Chrome and Firefox that opens burndrop links in a
bundled copy of the drop page. What it protects against, how it works, how to
install it, and its permissions are described in
[docs/browser-extension.md](../docs/browser-extension.md). This file is the
build and test reference.

## Build

The extension bundles the page that `web/build.mjs` produces, so build the
page first.

```sh
cd web && npm install && node build.mjs
cd ../extension && npm install
npm run typecheck
npm run build
```

`npm run build` writes `dist/chrome/`, `dist/firefox/`, the reproducible
packages `dist/burndrop-extension-chrome.zip` and
`dist/burndrop-extension-firefox.zip`, and a `.sha256` file next to each zip.

The version comes from `--version` or `BURNDROP_VERSION` (Chrome requires one
to four dot separated integers; a leading `v` is dropped) and defaults to
`0.0.0`:

```sh
node build.mjs --version 1.2.3
```

`node build.mjs --test` (or `BURNDROP_EXTENSION_TEST=1`) writes
`dist/chrome-test/` and `dist/firefox-test/` with the localhost host
permissions granted up front for the test suite. Those builds are never
zipped and are not for distribution.

`npm run icons` regenerates `icons/*.png` from `scripts/make-icons.mjs`.

## Test

Unit tests (origin validation, the zip writer):

```sh
npm run test:unit
```

End-to-end tests drive the test build in headless Chromium against the real
relay binary, which `web/e2e/build-relay.mjs` builds with the page embedded
(Go must be on `PATH`). Playwright's Chromium is needed once:
`npx playwright install chromium`.

```sh
node ../web/e2e/build-relay.mjs
npm run test:e2e
```

`npm test` runs the unit tests, the test build, and the end-to-end suite. The
relay listens on port 8941 (override with `BURNDROP_EXTENSION_E2E_PORT`) so
the suite can run alongside the web suite.
