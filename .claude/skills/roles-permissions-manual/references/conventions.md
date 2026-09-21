# Conventions behind the manual

These are the rules the manual documents. Re-read the sources below (especially
`client-ui-next`) when refreshing the manual — if a convention changed, update this
file **and** the matching narrative in `assets/manual-template.html` before regenerating.

## Where the truth lives

| What | Source of truth | Notes |
|------|-----------------|-------|
| Packages, entities, per-entity blocks, custom actions | `<configs>/permissions/*.permission` | Same files the platform loads. The generator parses these. |
| Roles (name, parent, attached blocks) | `<configs>/roles/*.role` | Drives §12. |
| IAM screens & flow (Users / Roles / User Group, create-role, attach-permissions dialog, group roles) | `client-ui-next` → `app/iam/**`, `lib/navigation/navPermission.ts`, `lib/iam/*` | Drives the §11 walkthrough narrative + mockups. Check here for UI changes. |
| CRUD verbs & action naming | authrs `src/policy/schema.rs` (`CRUD_VERBS`, `EXTENSIBLE_VERBS`) and `client-ui-next` SDK | Stable; see below. |

`<configs>` is a per-tenant repo (e.g. `siemens-energy-configs`) and lives in a
different directory on each machine — never hardcode it; discover or ask.

## Permission (building-block) naming

A `.permission` file's `name` is the building block a user attaches to a role:

- `<Package> - <Level>` — whole package (e.g. `Siemens - Admin`)
- `<Package> - <Entity> <Level>` — one entity (e.g. `Manufacturing Essential - Materials Editor`)
- `<Package> - Custom - <action>` — a custom action (e.g. `… - Custom - reopenMilestoneTicket`)

Level is always the **last word**: `Viewer`, `Editor`, or `Admin`.

## Access levels → actions

Underlying action names follow `verb + PascalCase(table)` (e.g. `getMaterials`).

| Level | Verbs granted |
|-------|---------------|
| Viewer | `get` |
| Editor | `get`, `post`, `patch`, `put`, `archive` |
| Admin | all seven: `get`, `post`, `patch`, `put`, `delete`, `archive`, `unarchive` |

CRUD verbs: `get, post, patch, put, delete, archive, unarchive`.
Extensible-field verbs (extensible tables only): `getExtensibleFields`,
`putExtensibleFields`, `deleteExtensibleFields`.

## Resource path format

`service:<svc>/package:<pkg>/table:<table>[/column:<col>]` — most-general to most-specific.
The generator reads `package:` and `table:` from each statement's `resources`.

## What the generator rewrites vs. leaves alone

Rewrites (data-driven): header "Packages:" pill, sidebar package links
(`<!-- GEN:navpackages -->`), §8 `#packages`, §12 `#example-roles`,
§16 `#reference-all`, and the §14 quick-ref "Packages" row.

Left untouched (narrative/UX): everything else — concepts, access-level explanation,
the §11 walkthrough steps and mockups, best practices, troubleshooting. Update those
by editing `assets/manual-template.html` directly when the UI or policy changes.
