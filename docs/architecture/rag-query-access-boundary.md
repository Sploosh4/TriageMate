# RAG Query Case-Hostname Boundary

**Date:** 2026-07-14
**Status:** IMPLEMENTED and approved in GitHub Issue #58; fail-closed follow-up merged in PR #76

## Decision

`rag_query` is scoped to the hostname of the case under investigation. The
hostname is supplied by server-controlled application context, not selected by
the LLM.

The model-facing tool schema exposes only an optional `cwe_class` filter. It
does not expose `hostname` or a free-form `query_text` asset selector.

## Enforcement

`execute_tool()` receives `case_hostname` separately from the model-generated
tool parameters and applies the boundary before dispatch:

1. A `rag_query` call without `case_hostname` fails closed and does not call
   the RAG backend.
2. A model-supplied `hostname` that differs from `case_hostname` is rejected
   before server-side injection.
3. For an allowed call, `execute_tool()` injects `case_hostname` into a copy of
   the parameters.
4. `_rag_query(hostname, cwe_class)` calls
   `query_rag(hostname, cwe_class=...)` using that server-provided hostname.

This prevents a prompt-injected or compromised model from choosing another
asset while retaining an optional CWE filter for the current case.

## Verification

Regression coverage in `backend/tests/test_tier2_agent.py` verifies:

- no case hostname: failure, with the RAG backend not called;
- mismatched hostname: rejected before dispatch;
- valid case hostname: injected into the RAG query;
- optional CWE filtering: preserved.

PR #75 implemented the server-injected boundary. PR #76 corrected the missing
hostname path to fail closed. Both PRs passed the GitHub Actions test matrix.

## References

- `backend/pipeline/tier_2/tools.py`
- `backend/tests/test_tier2_agent.py`
- GitHub Issue #58
- GitHub PRs #75 and #76
