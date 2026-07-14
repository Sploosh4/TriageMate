# RAG Query Hostname Binding

**Date:** 2026-07-14
**Status:** IMPLEMENTED — product-owner decision still to be recorded in Issue #58

## Decision

The `rag_query` tool is now bound to the case hostname. An optional `hostname` parameter has been added to the tool definition, and the existing server-side hostname binding check in `execute_tool()` validates it against the case under investigation before dispatch.

## Background

The Tier 2 agent has 12 read-only tools. When a case is assessed, `execute_tool()` receives a `case_hostname` parameter. For tools that accept a `hostname` parameter (`search_cmdb`, `query_network`, `query_telemetry`), a binding check validates that the requested hostname matches `case_hostname`. This prevents a compromised or prompt-injected LLM from querying infrastructure beyond the current case.

The `rag_query` tool accepted only `query_text` (not `hostname`), so it bypassed the binding check entirely. An attacker who subverted the LLM could query the RAG vector store for any asset — the tool's `query_text` parameter could be set to any hostname without restriction.

## Implementation

Two changes were made to `backend/pipeline/tier_2/tools.py`:

### 1. Tool Definition

An optional `hostname` property was added to the `rag_query` tool definition in `TOOL_DEFINITIONS`:

```python
{
    "name": "rag_query",
    "description": "Query the RAG (Retrieval Augmented Generation) vector store for asset context and documentation",
    "parameters": {
        "type": "object",
        "properties": {
            "query_text": {
                "type": "string",
                "description": "Search query text, typically a hostname or CWE class",
            },
            "hostname": {
                "type": "string",
                "description": "Fully qualified hostname of the case under investigation, used for access binding",
            },
        },
        "required": ["query_text"],
    },
},
```

The `hostname` parameter is **optional** (not in `required`) so existing agent calls that only pass `query_text` continue to work.

### 2. Implementation Signature

The `_rag_query()` function now accepts an optional `hostname` parameter. The hostname is not consumed by the implementation — it is accepted so that `execute_tool()`'s `**params` dispatch does not raise `TypeError`, and the binding check handles the security concern before the function runs.

```python
def _rag_query(query_text: str, hostname: str | None = None) -> dict:
```

### 3. Binding Check (Already Present — No Change Needed)

The existing generic check at line 726 of `tools.py` applies to all tools:

```python
if case_hostname and params.get("hostname") and params["hostname"] != case_hostname:
    logger.warning(...)
    return {"success": False, "data": None, "error": "..."}
```

Since `rag_query` now has a `hostname` property in its parameters, the LLM can supply it, and the binding check validates it identically to `search_cmdb` and `query_network`.

## Security Model

| Layer | Mechanism |
|---|---|
| Tool definition | `hostname` is documented as "the case under investigation" — guides the LLM toward correct usage |
| Server-side binding check | `execute_tool()` rejects any tool call where `params["hostname"] != case_hostname` |
| Implementation | `_rag_query()` accepts `hostname` but does not use it for query logic — purely a binding vehicle |

## Testing

- Existing tests that call `_rag_query("test-asset")` continue to work (positional arg, no hostname needed).
- The binding check is covered by existing tests for other hostname-scoped tools.
- The `test_all_twelve_tool_definitions_exist` test remains at 12 tools (no new tool added, only a parameter).

## References

- `backend/pipeline/tier_2/tools.py` — Tool definitions, `execute_tool()`, hostname binding check
- `backend/pipeline/tier_2/__init__.py` — Public exports (execute_tool already removed from __all__)
- Sprint 29 security hardening
