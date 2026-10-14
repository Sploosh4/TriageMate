# Domain documents

This repository uses a single domain context.

Before exploring domain behaviour, read `CONTEXT.md` at the repository root when
it exists. Read relevant decisions under `docs/adr/` when that directory exists.
Their absence is not a blocker; continue without proposing empty documents.

Use terminology defined in `CONTEXT.md` for issues, proposals, hypotheses, and
tests. If a needed term is missing, first check whether the codebase already uses
another term. Record a genuine unresolved terminology gap for domain modelling.

Surface any proposed change that conflicts with an existing ADR. Name the ADR and
explain why the decision may need reconsideration instead of silently replacing it.

The expected lazy layout is:

```text
/
├── CONTEXT.md
├── docs/adr/
└── source directories
```

Create domain documents only when the project resolves terms or architectural
decisions that need a durable source of truth.
