# Triage labels

The engineering skills use these five canonical triage roles.

| Skill role | GitHub label | Meaning |
| --- | --- | --- |
| `needs-triage` | `needs-triage` | A maintainer must evaluate the issue |
| `needs-info` | `needs-info` | More information is required from the reporter |
| `ready-for-agent` | `ready-for-agent` | The issue is specified for an unattended agent |
| `ready-for-human` | `ready-for-human` | The issue requires human implementation |
| `wontfix` | `wontfix` | The issue will not be actioned |

When a skill refers to a triage role, use the matching GitHub label in this table.

Each open work issue has exactly one canonical triage role. Use `needs-triage`
when a new or existing issue has no reviewed role. Remove the previous triage role
when the role changes. Do not infer `wontfix` or close an issue without the
authority required by `AGENTS.md`.
