---
name: frontend-engineering
description: HTML, CSS, JavaScript, DOM manipulation, Fetch API, vanilla JS SPA, UI components. Use when editing frontend/ files, index.html, CSS, or JavaScript.
---

# TriageMate Frontend Engineering

## GitHub Workflow

For repository coordination, load `github-basics`; report branch, SHA, and verification evidence to the Commander, which delegates GitHub lifecycle work to `git-steward`.

## Architecture
- Vanilla JavaScript SPA (no framework, no npm, no bundler)
- FastAPI serves `frontend/index.html` at root
- Single CSS file: `frontend/css/triagemate.css`
- Component modules in `frontend/js/components/`

## Key Files
- `frontend/index.html` — SPA shell with all screens
- `frontend/css/triagemate.css` — all styling
- `frontend/js/api.js` — HTTP client with Bearer token auth + 401 auto-refresh
- `frontend/js/app.js` — application state, navigation, event wiring
- `frontend/js/components/auth.js` — login modal
- `frontend/js/components/queue.js` — sortable table + filter controls
- `frontend/js/components/caseView.js` — 4-panel detail layout
- `frontend/js/components/metricBoxes.js` — summary stat cards
- `frontend/js/components/reviewQueue.js` — flagged cases listing
- `frontend/js/components/demoControls.js` — demo mode panel
- `frontend/js/components/driftDashboard.js` — drift metrics charts

## Design System (from triagemate.css + demo-reference.html)
- Primary action blue: #2563eb
- Severity bands: green (Low), yellow (Medium), orange (Critical), red (Very Critical)
- Background: white cards on #f8fafc page
- Body text: #1e293b, secondary: #64748b
- Component naming: BEM-like `.component-name-element`

## Security Rules
- Use `textContent` for all dynamic strings — never `innerHTML` for untrusted data
- Event delegation via `app.js` for keyboard shortcuts (Escape for back)

## Visual Reference
`demo-reference.html` is the canonical visual spec — all changes must match it exactly.

## Related Skills
- `ux-designing` — visual design, color palette, component library, accessibility, user-facing copy. Load this when making any UI, layout, or styling changes.
- `triage-toolbox` — dev server, Docker commands, testing, linting.
