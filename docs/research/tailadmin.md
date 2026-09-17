# TailAdmin Pro HTML: what we have and how it can be used

Status: Phase 0 finding. License wording is being verified against tailadmin.com/license and will be quoted in section 3 once confirmed.

## 1. What is in the archive

Source: `tailadmin-html-pro-2.4.zip` (9.7 MB), extracted to a scratch folder outside the project. Nothing from it has been copied into the project folder.

| Item | Finding |
|---|---|
| Product and version | TailAdmin Pro, HTML edition, version 2.4.0, released September 13, 2026 (per the bundled README update log) |
| CSS framework | Tailwind CSS v4.3.x via `@tailwindcss/postcss`, plus `@tailwindcss/forms`. No `tailwind.config.js`; the whole theme is an `@theme` block in `src/css/style.css` |
| Interactivity | Alpine.js v3.17.x with `@alpinejs/persist`. Dark mode, dropdowns, sidebar state and data tables are Alpine components registered in `src/js/index.js` |
| Build | Webpack 5, Babel 8, `html-loader` with a custom `<include src="...">` preprocessor for HTML composition, `mini-css-extract-plugin`, `copy-webpack-plugin`. Node 22.18 or later |
| Other libraries | ApexCharts, FullCalendar, Swiper, jsvectormap, Leaflet, MapLibre GL, flatpickr, Dropzone, Prism, Floating UI, i18next, temporal-polyfill |
| Content | 348 HTML files (pages and partials), 71 JS files, 2 CSS files, image assets. Includes auth pages (`signin.html`, `signup.html`, `reset-password.html`, `two-step-verification.html`) which are the closest layout to a one-card page |
| Fonts | `style.css` imports the Outfit font from Google Fonts at runtime (`fonts.googleapis.com`). Outfit itself is published under the SIL Open Font License |
| Dark mode | Class based: `@custom-variant dark (&:is(.dark *))`, toggled by adding `.dark` to `<body>`, persisted in `localStorage` |
| License file | **None in the archive.** `package.json` says `"license": "ISC"`, which is the npm default and not a grant. The README says: "Refer to our LICENSE page for more information" and links to tailadmin.com/license |
| Agent instructions | The archive ships an `AGENTS.md` describing the repo map, Alpine conventions, and styling rules (theme tokens, `@utility` classes, no hardcoded hex colors) |

## 2. Design tokens worth reusing

These are the parts of the design system that give TailAdmin its look and that a one-card page needs. They are values, not code, and can be re-expressed in our own stylesheet.

- Font: Outfit (self-hosted in our build; never loaded from Google Fonts at runtime).
- Colors: `brand` scale (500 = `#465fff`, 600 = `#3641f5`), `gray` scale (25 to 950, 900 = `#101828`), `success` (500 = `#12b76a`), `error` (500 = `#f04438`), `warning` (500 = `#f79009`).
- Type scale: `text-theme-xs` 12/18, `text-theme-sm` 14/20, `text-theme-xl` 20/30, `text-title-xs` 24/32, `text-title-sm` 30/38, `text-title-md` 36/44.
- Shadows: `shadow-theme-xs` through `shadow-theme-xl`, and `shadow-focus-ring` (`0 0 0 4px rgba(70, 95, 255, 0.12)`).
- Radius and spacing: cards use `rounded-2xl` with `border border-gray-200` (dark: `border-gray-800`), inputs use `rounded-lg h-11 px-4`, primary buttons use `rounded-lg px-4 py-3 text-sm font-medium bg-brand-500 hover:bg-brand-600`.
- Breakpoints: `2xsm` 375px, `xsm` 425px, plus the Tailwind defaults.

## 3. License findings and what can go into a public repository

Verified on 2026-09-17 against tailadmin.com/license, tailadmin.com/pricing, and the docs FAQ pages.

The license page defines three Pro tiers and nothing else:

| Tier | Seats | Projects | SaaS end product |
|---|---|---|---|
| Starter | "Seats: 1" | "Projects: 3 Projects" | "Not Valid for SaaS End Product" |
| Business | "Seats: 3" | "Projects: 10 Projects" | "Not Valid for SaaS End Product" |
| Extended | "Seats: 10" | "Projects: Unlimited" | "Valid for SaaS End Product with Redistribution License" |

The pricing FAQ defines the terms:

- "SaaS end product refers to license and permission to redistribute your application code along with the TailAdmin template files as an integral part of your final product which is only available for Extended plan."
- "Seats refer to the number of developers permitted to collaborate on the project and distribute and share TailAdmin resources."
- "The term projects refers to the number of projects/websites/tool/product that can be built or developed using TailAdmin."

The docs FAQ adds: "the Starter and Business licenses do not cover SaaS applications."

No TailAdmin page addresses open-source projects or public repositories at all. The free community edition is a separate product: "The community edition of TailAdmin is released under the MIT License."

What follows for a public repository:

1. **Pro source files cannot be committed.** Redistribution exists only in the Extended tier, and even there it is framed as template files shipped "as an integral part of your final product", not as source anyone can copy from a public repository. Sharing is also seat-limited, and a public repo has unlimited readers. Whatever tier was purchased, committing `src/`, `partials/`, or `style.css` from the Pro archive is outside the license.
2. **Using Pro as a reference is fine.** Nothing in the license restricts building a product with it, and design tokens (colors, sizes, radii, shadows) are values, not licensed files.
3. **The free edition is MIT** and could be vendored, but it is not needed for a one-card page.
4. The `ISC` string in the Pro `package.json` is npm boilerplate, not a grant, and must not be relied on.

If the owner wants written certainty, one email to TailAdmin asking whether a modified component may appear in a public Apache-2.0 repository would settle it. The recommended approach below does not depend on the answer.

## 4. Recommended approach

Use TailAdmin Pro as the **design reference**, not as vendored source.

1. **Write our own markup.** The drop page is one card with one field, a context panel, a button, and a status area. That is roughly 150 lines of HTML. Writing it ourselves in Tailwind classes that follow the TailAdmin conventions (same tokens, same radii, same spacing rhythm) produces the same look with no Pro files in the repo.
2. **Re-express the tokens.** Our `src/styles.css` defines an `@theme` block with the brand, gray, success, error and warning scales, the Outfit font, the type scale, and the shadows listed above. Color values and sizes are not copyrightable expression; the composed template files are.
3. **Self-host the font.** Outfit is OFL licensed. We subset it to Latin, weights 400 and 600, and inline it as base64 WOFF2 in the single-file page. No request to Google Fonts ever happens.
4. **No Alpine.js.** The page needs a show/hide toggle, copy, a countdown, a theme toggle, and state transitions. That is vanilla JavaScript. This also avoids the CSP question entirely (standard Alpine needs `unsafe-eval`; the CSP build restricts expressions and still adds a framework to audit).
5. **Compile Tailwind at build time** with the Tailwind v4 CLI, tree-shaken to the classes the page uses, and inline the result into the single-file page. No CDN.
6. **Keep the Pro archive out of the repository and out of git history**, including screenshots of Pro pages. The extension reuses our page bundle, so it inherits the same clean status.

If the license text turns out to permit committing modified Pro components to a public repository, the recommendation still stands: a one-card page does not benefit from vendoring a 348-page template, and a clean-room page is simpler to audit and to hash.
