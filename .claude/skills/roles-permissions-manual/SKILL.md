---
name: roles-permissions-manual
description: >-
  Generate or refresh the Roles & Permissions configuration manual (a self-contained
  HTML handbook for support and implementation teams) from the authoritative repos —
  a tenant's *-configs repo (e.g. siemens-energy-configs) for packages/roles/permissions,
  and client-ui-next for the IAM UI conventions. Use this whenever the user wants to
  update, regenerate, or rebuild the roles/permissions/packages documentation, add a new
  package or entity to the manual, refresh the building-block (Viewer/Editor/Admin)
  reference, sync the doc after config changes, or produce a fresh HTML manual — even if
  they just say "update the permissions doc", "regenerate the RBAC manual", or "the
  packages changed, update the guide". Also use it after editing the manual's narrative so
  the data sections stay in sync.
---

# Roles & Permissions manual generator

This skill produces a single self-contained HTML manual (no server, no external images —
UI screens are inline mockups) explaining how to configure roles, permissions and packages.
It keeps the **data sections** in lockstep with the real config repo, while preserving the
hand-written narrative and walkthrough.

## Inputs (repos live in different folders per machine — discover or ask)

1. **`<configs>`** — a per-tenant config repo containing `permissions/*.permission` and
   `roles/*.role` (e.g. `siemens-energy-configs`, often nested under a `config_repos/` folder).
   This is the source of truth for packages, entities, building blocks and roles.
2. **`client-ui-next`** — the IAM front end. Source of truth for the *UI flow* the
   walkthrough describes (Users / Roles / User Group, the create-role screen, the
   attach-permissions dialog, group roles).

The generator auto-discovers both by searching sibling/parent folders. **If either is not
found, ask the user for the path** rather than guessing — do not hardcode machine-specific
paths.

## Steps

1. **Locate the repos.** Run the generator (step 3); it prints the paths it discovered. If
   it errors that it can't find `<configs>`, ask the user where their `*-configs` repo is and
   pass `--configs`. Confirm the discovered `client-ui-next` is the right one too.

2. **Check `client-ui-next` for convention/UX drift** (only the *narrative* — the generator
   handles data). Skim `app/iam/**`, `lib/navigation/navPermission.ts`, and `lib/iam/*` for
   changes to the IAM screens, the create-role flow, or how permissions attach to roles.
   Cross-check against `references/conventions.md`. If something changed (e.g. a new IAM
   screen, renamed menu, a new access level), update `references/conventions.md` and edit the
   affected narrative/mockups in `assets/manual-template.html` **before** regenerating.
   If nothing changed, skip to step 3.

3. **Regenerate the data sections into a fresh HTML:**

   ```bash
   python3 scripts/generate_manual.py --out <path>/roles-and-permissions.html
   # add --configs / --client-ui if auto-discovery fails
   ```

   It rewrites (and only these): the header "Packages:" pill, the sidebar package links,
   §8 Packages & entities, §12 Example roles, §16 the full building-block reference, and the
   §14 quick-ref packages line. Everything else in the template is preserved verbatim.

4. **Fill any new entity descriptions.** The script prints a per-package summary. If a new
   entity appears, it will show a generic "<Name> records" line in the output. Add a friendlier
   one-liner to `references/entity-descriptions.json` (keyed by table name, or `pkg_id/table`)
   and re-run. You can also pin package ordering there via `_package_order`.

5. **Verify.** Open the output HTML in a browser (it is fully self-contained). Confirm the
   package count, entity tables, building-block names and roles look right, and that the
   sidebar links jump correctly.

## Output

A fresh, self-contained `roles-and-permissions.html`. Default output is
`./roles-and-permissions.html`; for this project it belongs at
`docs/roles-and-permissions.html`. Send it to the user with SendUserFile (display: render).

## Bundled resources

- `assets/manual-template.html` — the full manual with the narrative, the §11 walkthrough
  and mockups, and `<!-- GEN:* -->` markers / section ids the generator targets. Edit this
  for any non-data change (wording, new walkthrough step, restyle).
- `scripts/generate_manual.py` — parses the configs and splices the data sections in.
- `references/entity-descriptions.json` — friendly per-entity one-liners + optional
  `_package_order`. Extend as packages grow.
- `references/conventions.md` — the naming/level/resource conventions and where each fact
  comes from. Read this when checking `client-ui-next` for drift.

## Notes

- The template is the *source*; the generated file is the *output*. To change narrative,
  edit the template, then regenerate so data stays consistent.
- Keep the manual JSON-free and plain-language — it is for support/implementation teams, not
  developers.
- Never hardcode absolute repo paths in the skill; they differ per machine.
