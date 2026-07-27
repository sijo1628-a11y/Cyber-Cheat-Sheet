# Cyber Cheat Sheet

An offline, single-page reference dashboard for SOC analysts, ethical hackers, blue teams
and cybersecurity students — Linux, Windows, PowerShell, Nmap, Wireshark, Splunk, KQL,
Sigma and YARA in one searchable site. Pure HTML/CSS/JavaScript, no frameworks, no backend,
no build step.

## Deploy to GitHub Pages

1. Create a new GitHub repository and push everything in this folder to it (keep the
   folder structure as-is — `index.html` must be at the repo root).
2. In the repo, go to **Settings → Pages**, set **Source** to the `main` branch / root,
   and save.
3. GitHub will publish the site at `https://<username>.github.io/<repo>/` within a
   minute or two. No configuration, Node.js, or build tools are required.

## Testing locally

Browsers block `fetch()` of local JSON files when a page is opened directly via
`file://` (a standard browser security restriction, not specific to this site — it
applies to any static site that loads JSON with `fetch`). To test locally before
deploying, serve the folder with any simple local web server, for example:

```bash
python3 -m http.server 8000
# then open http://localhost:8000 in your browser
```

or the VS Code "Live Server" extension. Once deployed to GitHub Pages (or any other
web host), it works with no extra steps.

## Adding or editing content

Every reference entry lives in a JSON file under `/data`, one file per category
(`linux.json`, `windows.json`, `powershell.json`, `nmap.json`, `wireshark.json`,
`splunk.json`, `kql.json`, `sigma.json`, `yara.json`). Each entry follows the same
shape:

```json
{
  "id": "linux-071",
  "category": "linux",
  "title": "Short display name",
  "code": "the actual command / query / filter / rule",
  "description": "One or two sentences on what it does",
  "example": "Optional — a fuller usage example",
  "output": "Optional — sample output",
  "notes": "Optional — a tip, caveat, or gotcha",
  "tags": ["tag-one", "tag-two"],
  "difficulty": "Easy | Medium | Hard"
}
```

`example`, `output` and `notes` are optional — leave them as empty strings to omit
that section from the card. `id` should stay unique within its file (and is used for
favorites/recently-viewed, so avoid changing an existing entry's `id` once published).

## What's included

- Global search across all categories, plus per-category search with difficulty and
  tag filters, instant highlighting, and result counts.
- Copy-to-clipboard on every card, with a toast confirmation.
- Favorites (stored in `localStorage`), with JSON export/import.
- Recently viewed, Command of the Day, and a random tip generator on the home page.
- Keyboard shortcuts: `/` focuses the nearest search box, `Esc` collapses expanded
  cards, `Ctrl/Cmd+C` copies whichever card is currently focused/hovered (when no
  text is selected).
- A print-friendly stylesheet (`Print` in the footer or `Ctrl/Cmd+P`).
- An installable PWA manifest and a service worker that caches the app shell and all
  data files, so the dashboard keeps working offline after the first successful load.
- A responsive layout (desktop / tablet / mobile) with a slide-in nav drawer on small
  screens.

## Content scope note

The dataset currently ships with roughly 330 real, accurate entries across the nine
categories (see the `data/` files) rather than the very largest figures mentioned in
the original brief (e.g. "300+ Linux commands") — the app is built to comfortably
scale to that volume, but hand-authoring thousands of individually accurate entries
in one pass would trade accuracy for filler. Add more entries at any time by following
the schema above; nothing else in the app needs to change.

## Disclaimer

Provided for educational and authorized-use reference purposes only. Some referenced
tools (e.g. Nmap, packet/credential analysis utilities) can be misused — only use them
against systems and networks you own or are explicitly authorized to test.
