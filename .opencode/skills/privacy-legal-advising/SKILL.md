---
name: privacy-legal-advising
description: Australian privacy law, data handling compliance, demo data safety review, vulnerability disclosure policy, WA government data classification. Use ONLY when assessing privacy/legal risk in data handling, demo scenarios, or implementing new data pipelines.
---

# Privacy & Legal Advising

## GitHub Workflow

Follow `github-basics`: only the user creates the task workspace through OpenCode; use its existing shared worktree and branch, and never create or switch workspaces, worktrees, or branches or use a manual/CLI fallback. Report the workspace path, branch, SHA, and verification evidence to the Commander; `git-steward` owns role-authorized Git/GitHub publishing actions. Do not encode a legal or privacy policy choice without explicit approval.

## Jurisdiction
- Australian Privacy Act 1988: Australian Privacy Principles (APPs), notifiable data breaches scheme
- WA-specific: WA Freedom of Information Act, State Records Act
- Australian Government: ACSC Essential Eight, ISM controls, PSPF alignment

## Data Classification (WA Government)
- Category 1: Public
- Category 2: Sensitive
- Category 3: Protected
- Category 4: Classified

## Application to TriageMate
- CVE data from NVD is public domain — no privacy concerns
- Internal CMDB data (hostnames, IPs, application inventories) may be Category 3
- Demo data must not inadvertently reference real WA government assets

## When to Apply This Skill
- Reviewing demo data for accidental real-asset references
- Validating mock CMDB entries
- Assessing scenario descriptions for realism vs. identifiability
- Evaluating data retention policies
- Flagging privacy/legal risk in new features or data pipelines
- Reviewing public-facing documentation for compliance

## Assessment Rules
1. Treat all internal hostnames, IPs, and application inventories as Category 3 unless proven otherwise
2. Fictional demo data MUST NOT contain real WA government hostnames, real IP ranges, or identifiable department information
3. When in doubt about legal compliance, flag it — do not assume acceptability
4. Provide clear rulings: approved, amend (with suggested fix), or rejected
