#!/usr/bin/env python3
"""
Regenerate the data-driven sections of the Roles & Permissions manual HTML from
the authoritative config repo (e.g. siemens-energy-configs).

What it rewrites in the template (everything else is left untouched):
  - the header "Packages:" pill
  - the sidebar package sub-links (between <!-- GEN:navpackages --> markers)
  - section  #packages       (§8 Packages & entities)
  - section  #example-roles  (§12 Example roles)
  - section  #reference-all   (§16 building-block reference)
  - the "Packages" row of the §14 quick reference

Data source: <configs>/permissions/*.permission  and  <configs>/roles/*.role
These are the same files the platform loads, so the manual always matches reality.

Usage:
  python3 generate_manual.py --configs /path/to/siemens-energy-configs \
                             --template assets/manual-template.html \
                             --out /path/to/roles-and-permissions.html
Paths are auto-discovered when omitted; the script prints what it used.
"""
import argparse, glob, html, json, os, re, sys

LEVELS = ("Viewer", "Editor", "Admin")
LEVEL_MEANING = {
    "Viewer": "View / list records only.",
    "Editor": "Create, edit and archive records (no delete/restore).",
    "Admin": "Full control — create, edit, archive, delete and restore.",
}


# ---------- discovery -------------------------------------------------------
def is_configs_dir(p):
    return os.path.isdir(os.path.join(p, "permissions")) and os.path.isdir(os.path.join(p, "roles"))


def discover_configs(start):
    # walk up from start, checking each dir and its children
    cur = os.path.abspath(start)
    seen = set()
    roots = []
    for _ in range(6):
        roots.append(cur)
        parent = os.path.dirname(cur)
        if parent == cur:
            break
        cur = parent
    roots.append(os.path.expanduser("~/Documents/GitHub"))
    for root in roots:
        if not os.path.isdir(root) or root in seen:
            continue
        seen.add(root)
        if is_configs_dir(root):
            return root
        # children and grandchildren (repos are often nested, e.g. config_repos/<tenant>-configs)
        for pat in ("*", "*/*"):
            hits = [c for c in sorted(glob.glob(os.path.join(root, pat)))
                    if os.path.isdir(c) and is_configs_dir(c)]
            # prefer a directory whose name ends with -configs
            hits.sort(key=lambda c: (not c.rstrip("/").endswith("-configs"), c))
            if hits:
                return hits[0]
    return None


def discover_client_ui(start):
    cur = os.path.abspath(start)
    roots = []
    for _ in range(6):
        roots.append(cur)
        parent = os.path.dirname(cur)
        if parent == cur:
            break
        cur = parent
    roots.append(os.path.expanduser("~/Documents/GitHub"))
    for root in roots:
        for child in glob.glob(os.path.join(root, "client-ui-next")):
            if os.path.isdir(child):
                return child
    return None


# ---------- parsing ---------------------------------------------------------
def pretty(table):
    return " ".join(w.capitalize() for w in table.replace("-", "_").split("_"))


def parse_configs(configs):
    """Return packages{ pkg_id: {display, entities{table:{display,levels}}, customs[], whole:set} }
       and roles[ {name,parent,permissions[]} ]."""
    packages = {}
    for path in sorted(glob.glob(os.path.join(configs, "permissions", "*.permission"))):
        try:
            doc = json.load(open(path, encoding="utf-8"))
        except Exception as e:
            print(f"  ! skipping {os.path.basename(path)}: {e}", file=sys.stderr)
            continue
        name = doc.get("name", "")
        stmts = doc.get("document", {}).get("statements", [])
        # package id + table from resources
        pkg_id, table = None, None
        for s in stmts:
            for r in s.get("resources", []):
                m = re.search(r"package:([^/]+)", r)
                if m:
                    pkg_id = pkg_id or m.group(1)
                mt = re.search(r"table:([^/]+)", r)
                if mt:
                    table = table or mt.group(1)
        if not pkg_id:
            continue
        # Names look like "<Pkg> - <Level>" (whole package),
        # "<Pkg> - <Entity words> <Level>" (per entity, level is the LAST WORD),
        # or "<Pkg> - Custom - <action>" (custom action).
        head, _, rest = name.partition(" - ")
        pkg_display = head.strip() or pkg_id
        rest = rest.strip()
        pk = packages.setdefault(pkg_id, {"display": pkg_display, "entities": {}, "customs": [], "whole": set()})
        pk["display"] = pkg_display
        if rest in LEVELS:                                            # <Pkg> - <Level>
            pk["whole"].add(rest)
        elif rest.lower().startswith("custom - "):                    # <Pkg> - Custom - <action>
            pk["customs"].append(rest.split(" - ", 1)[1].strip())
        elif rest.split() and rest.split()[-1] in LEVELS and table:   # <Pkg> - <Entity> <Level>
            level = rest.split()[-1]
            entity_display = re.sub(r"\s+(Viewer|Editor|Admin)$", "", rest).strip()
            ent = pk["entities"].setdefault(table, {"display": entity_display or pretty(table), "levels": set()})
            ent["levels"].add(level)
    roles = []
    for path in sorted(glob.glob(os.path.join(configs, "roles", "*.role"))):
        try:
            doc = json.load(open(path, encoding="utf-8"))
        except Exception as e:
            print(f"  ! skipping role {os.path.basename(path)}: {e}", file=sys.stderr)
            continue
        roles.append({"name": doc.get("name", ""), "parent": doc.get("parent"),
                      "permissions": doc.get("permissions", [])})
    return packages, roles


def load_descriptions(skill_dir):
    p = os.path.join(skill_dir, "references", "entity-descriptions.json")
    if os.path.exists(p):
        try:
            return json.load(open(p, encoding="utf-8"))
        except Exception:
            pass
    return {}


def describe(descs, pkg_id, table, display):
    return descs.get(f"{pkg_id}/{table}") or descs.get(table) or f"{display} records"


# ---------- rendering -------------------------------------------------------
def e(s):
    return html.escape(str(s), quote=True)


def render_nav(pkgs, order):
    out = ["    <!-- GEN:navpackages START -->"]
    for i, pid in enumerate(order, 1):
        out.append(f'    <a class="sub2" href="#pkg-{e(pid)}">8.{i} · {e(pkgs[pid]["display"])}</a>')
    out.append("    <!-- GEN:navpackages END -->")
    return "\n".join(out)


def render_packages_section(pkgs, order, descs):
    P = ['  <section id="packages">', "    <h2>8 · Packages &amp; entities</h2>"]
    n = len(order)
    P.append(f"    <p>This environment has <b>{n} package{'s' if n!=1 else ''}</b>. "
             "Each entity supports the standard <b>Viewer / Editor / Admin</b> building blocks.</p>")
    for i, pid in enumerate(order, 1):
        pk = pkgs[pid]
        P.append(f'    <h3 id="pkg-{e(pid)}">8.{i} · {e(pk["display"])}</h3>')
        P.append('    <table><thead><tr><th>Entity</th><th>What it holds</th></tr></thead><tbody>')
        for table, ent in sorted(pk["entities"].items(), key=lambda kv: kv[1]["display"].lower()):
            P.append(f'      <tr><td>{e(ent["display"])}</td>'
                     f'<td>{e(describe(descs, pid, table, ent["display"]))}</td></tr>')
        P.append("    </tbody></table>")
        whole = " / ".join(l for l in LEVELS if l in pk["whole"]) or "—"
        note = f'    <div class="callout"><b>Whole-package blocks:</b> {e(pk["display"])} - {whole}.'
        if pk["customs"]:
            cust = ", ".join(sorted(set(pk["customs"])))
            note += f'<br><b>Custom action{"s" if len(set(pk["customs"]))>1 else ""}:</b> <code>{e(cust)}</code>.'
        note += "</div>"
        P.append(note)
    P.append("  </section>")
    return "\n".join(P)


def render_reference_section(pkgs, order, descs):
    R = ['  <section id="reference-all">',
         "    <h2>16 · Building-block reference — every Viewer / Editor / Admin</h2>",
         '    <div class="callout"><b>How to read this:</b> each row is one entity. The block name is the '
         'base below with a level appended — <span class="lvl v">Viewer</span> '
         '<span class="lvl e">Editor</span> <span class="lvl a">Admin</span>.</div>',
         "    <table><thead><tr><th>Level</th><th>What it gives (any entity)</th></tr></thead><tbody>"]
    for lv, cls in (("Viewer", "v"), ("Editor", "e"), ("Admin", "a")):
        R.append(f'      <tr><td><span class="lvl {cls}">{lv}</span></td><td>{e(LEVEL_MEANING[lv])}</td></tr>')
    R.append("    </tbody></table>")
    for pid in order:
        pk = pkgs[pid]
        R.append(f'    <h3>{e(pk["display"])} <span class="pkg-tag">(prefix: '
                 f'<code>{e(pk["display"])} -</code>)</span></h3>')
        R.append('    <table><thead><tr><th>Block name (append Viewer / Editor / Admin)</th>'
                 "<th>Controls…</th></tr></thead><tbody>")
        for table, ent in sorted(pk["entities"].items(), key=lambda kv: kv[1]["display"].lower()):
            R.append(f'      <tr><td><code>{e(pk["display"])} - {e(ent["display"])}</code></td>'
                     f'<td>{e(describe(descs, pid, table, ent["display"]))}</td></tr>')
        R.append("    </tbody></table>")
        whole = " / ".join(l for l in LEVELS if l in pk["whole"]) or "—"
        line = f'    <p><b>Whole package:</b> <code>{e(pk["display"])} - {whole}</code>.'
        for c in sorted(set(pk["customs"])):
            line += f'<br><b>Custom:</b> <code>{e(pk["display"])} - Custom - {e(c)}</code>.'
        line += "</p>"
        R.append(line)
    R.append("  </section>")
    return "\n".join(R)


def render_roles_section(roles, pkgs):
    def shape(r):
        if not r["permissions"] and r["parent"]:
            return f'Inherits everything from <i>{e(r["parent"])}</i>.'
        pkgnames = []
        for perm in r["permissions"]:
            head = perm.split(" - ")[0]
            if head not in pkgnames:
                pkgnames.append(head)
        return f'{len(r["permissions"])} building block(s) across {e(", ".join(pkgnames)) or "—"}.'

    S = ['  <section id="example-roles">',
         "    <h2>12 · Example roles from this environment</h2>",
         "    <p>These real roles show how building blocks combine. Use them as templates.</p>",
         "    <table><thead><tr><th>Role</th><th>Inherits from</th><th>Rough shape</th></tr></thead><tbody>"]
    for r in sorted(roles, key=lambda r: r["name"].lower()):
        S.append(f'      <tr><td><b>{e(r["name"])}</b></td>'
                 f'<td>{e(r["parent"]) if r["parent"] else "—"}</td><td>{shape(r)}</td></tr>')
    S.append("    </tbody></table>")
    # worked example: the role touching the most packages, and the smallest non-empty role
    nonempty = [r for r in roles if r["permissions"]]
    if nonempty:
        biggest = max(nonempty, key=lambda r: len(r["permissions"]))
        smallest = min(nonempty, key=lambda r: len(r["permissions"]))
        for label, r in (("", biggest), ("", smallest)):
            blocks = " + ".join(r["permissions"][:12]) + (" …" if len(r["permissions"]) > 12 else "")
            S.append(f'    <div class="callout"><b>Worked example — {e(r["name"])} =</b> {e(blocks)}</div>')
    S.append('    <div class="callout tip"><b>Tip:</b> use a <b>parent role</b> when one role is '
             '"everything that role has, plus more" — the child inherits the parent\'s blocks '
             "instead of repeating them.</div>")
    S.append("  </section>")
    return "\n".join(S)


# ---------- splice ----------------------------------------------------------
def replace_section(html_text, section_id, new_html):
    pat = re.compile(r'  <section id="%s">.*?</section>' % re.escape(section_id), re.DOTALL)
    if not pat.search(html_text):
        print(f"  ! section #{section_id} not found in template", file=sys.stderr)
        return html_text
    return pat.sub(lambda _: new_html, html_text, count=1)


def replace_between(html_text, start, end, new_block):
    pat = re.compile(re.escape(start) + r".*?" + re.escape(end), re.DOTALL)
    return pat.sub(lambda _: new_block, html_text, count=1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--configs", help="path to the *-configs repo (has permissions/ and roles/)")
    ap.add_argument("--client-ui", help="path to client-ui-next (optional; conventions cross-check)")
    ap.add_argument("--template", help="template HTML (default: skill assets/manual-template.html)")
    ap.add_argument("--out", help="output HTML path (default: ./roles-and-permissions.html)")
    args = ap.parse_args()

    skill_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    template = args.template or os.path.join(skill_dir, "assets", "manual-template.html")
    out = args.out or os.path.join(os.getcwd(), "roles-and-permissions.html")

    configs = args.configs or discover_configs(os.getcwd())
    if not configs or not is_configs_dir(configs):
        print("ERROR: could not find a configs repo (needs permissions/ and roles/).\n"
              "Pass --configs /path/to/<tenant>-configs . Repos differ per machine, so ask the user.",
              file=sys.stderr)
        sys.exit(2)
    client_ui = args.client_ui or discover_client_ui(os.getcwd())

    print(f"configs   : {configs}")
    print(f"client-ui : {client_ui or '(not found — conventions from references/conventions.md)'}")
    print(f"template  : {template}")
    print(f"output    : {out}")

    pkgs, roles = parse_configs(configs)
    if not pkgs:
        print("ERROR: no packages parsed from permissions/*.permission", file=sys.stderr)
        sys.exit(2)
    descs = load_descriptions(skill_dir)
    # Preferred package order if declared, else alphabetical by display name.
    preferred = [p for p in descs.get("_package_order", []) if p in pkgs]
    order = preferred + sorted((p for p in pkgs if p not in preferred),
                               key=lambda pid: pkgs[pid]["display"].lower())

    doc = open(template, encoding="utf-8").read()
    doc = replace_between(doc, "<!-- GEN:navpackages START -->", "<!-- GEN:navpackages END -->",
                          render_nav(pkgs, order))
    doc = replace_section(doc, "packages", render_packages_section(pkgs, order, descs))
    doc = replace_section(doc, "example-roles", render_roles_section(roles, pkgs))
    doc = replace_section(doc, "reference-all", render_reference_section(pkgs, order, descs))
    # header pill + quick-ref packages line
    pkg_names = " · ".join(pkgs[p]["display"] for p in order)
    doc = re.sub(r'(<span class="pill">Packages: )[^<]*(</span>)', lambda m: m.group(1) + e(pkg_names) + m.group(2), doc)
    doc = re.sub(r'(<th>Packages</th><td>)[^<]*(</td>)', lambda m: m.group(1) + e(pkg_names) + m.group(2), doc)

    with open(out, "w", encoding="utf-8") as f:
        f.write(doc)

    print("\nSummary")
    for pid in order:
        pk = pkgs[pid]
        print(f"  {pk['display']:<24} {len(pk['entities'])} entities"
              + (f", custom: {', '.join(sorted(set(pk['customs'])))}" if pk['customs'] else ""))
    print(f"  roles: {len(roles)}")
    print(f"\nWrote {out}")


if __name__ == "__main__":
    main()
