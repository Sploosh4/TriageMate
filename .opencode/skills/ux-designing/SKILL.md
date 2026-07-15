---
name: ux-designing
description: Visual design, CSS architecture, layout, color palette, accessibility, user-facing copy/text. Use when making UI changes, styling, layout decisions, or reviewing visual consistency in the TriageMate frontend.
---

# TriageMate UX Design

## GitHub Workflow

Follow `github-basics`: only the user creates the task workspace through OpenCode; use its existing shared worktree and branch, and never create or switch workspaces, worktrees, or branches or use a manual/CLI fallback. Report the workspace path, branch, SHA, and verification evidence to the Commander; `git-steward` owns role-authorized Git/GitHub publishing actions.

## Visual Reference
`demo-reference.html` is the canonical visual spec — all changes must match it exactly.

## Color Palette
- Primary action blue: #2563eb
- Severity bands:
  - Green: Low
  - Yellow: Medium
  - Orange: Critical
  - Red: Very Critical
- Background: white cards on #f8fafc page
- Body text: #1e293b
- Secondary text: #64748b

## Component Library (in frontend/css/triagemate.css)
- `.metric-box` — summary stat cards (count + label)
- `.case-panel` — 4-panel case detail layout
- `.accordion` — expandable detail sections
- `.conflict-highlight` — yellow background + left border (text conflicts)
- `.substitution-block` — greyed-out container with "Substituted" label
- `.demo-controls` — demo mode panel (scenario picker, buttons)

## Conventions
- BEM-like naming: `.component-name-element`
- CSS custom properties for colors and spacing where possible
- `textContent` over `innerHTML` for security
- Keyboard shortcuts: Escape for back navigation
- Queue density: readable at 7-row minimum, 50-row maximum
- Event listeners wired through `app.js` for DOM-ready guarantees

## Accessibility
- WCAG contrast ratios
- Keyboard navigation
- Screen reader compatibility
