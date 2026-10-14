# TriageMate UI instructions

Follow [root project rules](../AGENTS.md) and [current scope](../docs/planning/PIVOT_SCOPE.md). Use ordinary React screens and a read-only SQL explorer, served by FastAPI in the application container. Do not restore Markdown rendering, notebook editing or native workstation startup.

Keep strict TypeScript and reusable components/tokens. Keep display models independent of collector transport. Present source records, timestamps and uncertainty honestly: unknown is not zero, absence is not proof of health, and an advisory does not prove device applicability.

The backend and restricted PostgreSQL reader enforce SQL protections. Classification corrections use a separate constrained API preserving original observations and correction provenance. Components must not bypass either boundary. Remote identity authentication and multi-user authorization are pending decisions.

Provide semantic controls, visible focus, native keyboard behavior, modal focus containment, Escape dismissal and focus restoration. Preserve dense evidence and narrow-screen usability. Keep necessary titles/labels without mini headings, slogans or generic success captions.

Run frontend lint, format, type/build and applicable browser checks, plus API/database checks for affected contracts; see [README](../README.md). Verify the updated running container UI in a new visible tab and leave it open. Keep scratch artifacts outside tracked source.
