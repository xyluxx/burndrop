# Name options

Checked on 2026-09-17: npm registry, PyPI, GitHub handle (user or organization), GitHub repository name search (top result by stars), `.dev` (Google Registry RDAP), `.io` (Identity Digital RDAP, with a DNS delegation check as a second signal). "Free" means not registered at check time; confirm at a registrar before buying.

## Recommended five

| Name | Tagline | npm | PyPI | GitHub handle | .dev | .io | Existing repos with this name |
|---|---|---|---|---|---|---|---|
| **burndrop** | Burn-after-reading secret drops between you and your AI agents. | free | free | free | free | free | 9, top is a 1-star file sharing project |
| **sealpost** | Sealed, one-time post for secrets, in both directions. | free | free | free | free | free | 2, no stars |
| **dropseal** | Seal a secret, drop it once, gone forever. | free | free | free | free | free | 2, no stars |
| **keyseal** | Seal a key. Hand it over once. | free | free | free | free | free | 2, top is a 2-star Go CLI around sops and age |
| **sealdrop** | Sealed one-time secret drops for humans and agents. | free | free | **taken** | free | **taken** | 15, top is a 3-star game mod |

## Working choice: burndrop

Reasons:
- Free everywhere that matters, including the GitHub handle, so the project can live at github.com/xyluxx/burndrop with matching npm, PyPI, and domain names.
- It says what the tool does in one word to the audience that matters: "burn after reading" is the one-time property, "dead drop" is the covert handoff.
- Eight characters, easy to type as a CLI (`burndrop request`), easy to say.
- No trademark collision found in software or security products.

sealdrop reads slightly more naturally but its GitHub handle and .io are taken, which is a real cost for a project that wants one name across every registry. If the owner prefers it anyway, the repo can live under the owner's account and the rename is a global replace.

## Checked and rejected

| Name | Why not |
|---|---|
| deaddrop | Taken on npm, PyPI, GitHub and .dev; also the original name of SecureDrop, and an existing DeadDrop project with docs |
| blinddrop | .io taken; a 1-star repo with the same name describes a similar idea (a local encrypted vault for secrets that agents use without receiving them) |
| cipherdrop | A 48-star privacy file-hosting project uses the name |
| secretdrop | SecretDrop.io (39 stars) and .dev taken |
| hushdrop, burnbox, glovebox, agentdrop, sealbox, dropvault, lockdrop | Taken on npm or PyPI or GitHub, several also on .dev; burnbox and sealbox are existing secret-sharing or secret-storage projects |
| airlock | Taken everywhere and collides with two security vendors (Airlock Digital, Ergon Airlock) |
| oneseal, quietdrop, oncedrop, passdrop, dropkey, hushkey, sealwire, mailslot, dropslot, blindrelay | GitHub handle or .dev taken, or an existing project in the same space (oneseal is a secrets-as-code tool) |
| keyhandoff | Free everywhere but long and literal; kept as a fallback |
