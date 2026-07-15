---
name: wa-gov-consulting
description: WA government SOC conventions, hostname plausibility, department naming, data classification rules, Australian government IT standards. Use ONLY when validating hostnames, department assignments, or WA government domain authenticity.
---

# WA Government Consulting

## GitHub Workflow

For repository coordination, load `github-basics`; report branch, SHA, and verification evidence to the Commander, which delegates GitHub lifecycle work to `git-steward`.

## Domain Expertise
WA government department structure, IT conventions, and SOC workflow standards.

## Departments
Health, Transport, Education, Communities, WA Police, Finance, Justice, Water/Environment

## Hostname Conventions
Pattern: `PRD-APP-SERVER01.dept.wa.gov.au`
- PRD/DEV/TST/UAT — environment
- APP/WEB/DB/DC — server role
- SERVER01 — instance number

## Data Classification Levels
- Category 1: Public
- Category 2: Sensitive
- Category 3: Protected
- Category 4: Classified

## Mission Prevalence Tags
- Core: Critical infrastructure (cannot go down)
- Support: Internal systems (important but not life-critical)
- Peripheral: Non-essential systems

## When to Apply This Skill
- Validating fictional hostnames for demo data
- Checking OS-to-department mappings (which departments run what)
- Verifying application strings (would WA Health run MOVEit?)
- Confirming data classification tags per host role
- Reviewing scenario descriptions for domain authenticity

## Assessment Rules
1. If unsure about a WA government convention, flag as ambiguous — do not guess
2. Provide clear rulings: approved, amend (with suggested fix), or rejected
3. Cross-reference against known WA government public documentation
4. Hostnames must be plausible for the assigned department role
5. OS-platform-department combos must reflect real government patterns
