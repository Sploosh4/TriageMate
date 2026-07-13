# Graphify Output Reliability — Findings and Remediation Specification

> **Status: CURRENT — ACTION REQUIRED**
>
> **Date:** 12 July 2026  
> **Scope:** The five generated files under `graphify_output/` and their generators
> in the sibling Graphify repository.  
> **Purpose:** Give an implementing agent an evidence-based specification for
> making Graphify outputs reproducible, provenance-aware, and safe to use as
> engineering references.

## Executive summary

The Graphify outputs are useful discovery aids, but they are not currently
reliable enough to be described as canonical documentation.

Two kinds of content are mixed together:

1. mechanically derived facts, such as imports, filenames, sizes, and feature
   counts; and
2. handwritten narrative embedded in generator source, such as active model
   versions, model objectives, thresholds, metrics, dates, and pipeline status.

Regeneration updates timestamps and filesystem observations but reproduces stale
handwritten claims. This creates a particularly dangerous failure mode: an old
claim appears newly verified because it sits in a freshly generated file.

The most serious confirmed examples are:

- `ml_inventory.md` says the current XGBoost output is binary, while training
  uses `multi:softprob` with five classes and inference exposes per-window
  probabilities.
- `ml_inventory.md` identifies EPSS v3 as current even though the loader prefers
  v4 and the project roadmap identifies v4 as active.
- `ml_inventory.md` states both 419 and 420 XGBoost input columns.
- `feature_parity.md` reports matching counts while its heuristic positional
  comparison still reports 21 mismatches.
- `knowledge_graph.json` mixes database, source-code, and synthetic fallback
  records without provenance on individual nodes and edges.
- `api_deps.md` is an import map, not a function caller-to-callee graph.
- local gitignored artifacts and absolute workstation paths make output vary by
  machine.

The correct fix is to change the generators, add generator tests, regenerate,
and only then update the TriageMate documentation that describes the outputs.
Do not hand-edit files under `graphify_output/`.

## Repository boundary

This work spans two separate repositories:

| Repository | Path | Responsibility |
|---|---|---|
| TriageMate | `/home/jpc/Documents/Cybersecurity (Temp)/TriageMate/TriageMate MVP` | Source code being analysed, generated outputs, project documentation and integration commands |
| Graphify | `/home/jpc/Documents/Cybersecurity (Temp)/graphify` | Generator implementations and generator tests |

The relevant Graphify generator files are:

- `generators/ml_inventory.py`
- `generators/feature_parity.py`
- `generators/knowledge_graph.py`
- `generators/api_deps.py`
- `generators/file_tree.py`

Changes to Graphify should be committed in the Graphify repository. Regenerated
outputs and TriageMate integration/documentation changes should be committed in
TriageMate. An implementing agent must inspect both worktrees before editing and
must preserve unrelated changes in each.

## Reliability standard

Every generated claim must fit one of these classes:

| Class | Meaning | Permitted presentation |
|---|---|---|
| Derived | Parsed directly from tracked source or deterministic metadata | May be presented as a verified fact with its source |
| Observed | Found in the current local environment, such as an ignored model artifact or database | Must be labelled local and non-reproducible, with presence and source path |
| Synthetic | Created by a demo fixture or fallback dataset | Must be labelled synthetic on every affected record |
| Declared | Read from an explicit project manifest maintained as source data | May be presented as declared configuration, not independently verified fact |
| Unknown | Cannot be derived safely | Must say unknown; the generator must not substitute a hardcoded guess |

Generated prose must never silently convert an observed, synthetic, or declared
value into a universally true project fact.

Each output should include generation metadata sufficient to reproduce it:

- TriageMate commit SHA and dirty/clean status
- Graphify commit SHA and dirty/clean status
- generation timestamp and schema version
- generation mode, such as `tracked-only` or `include-local-artifacts`
- source files or source categories used
- warnings and derivation failures

Do not embed absolute developer paths in committed output.

## Finding 1 — ML inventory contains freshly generated stale claims

### Verified defects

The current `graphify_output/ml_inventory.md` contains all of the following:

| Claim | Actual evidence | Verdict |
|---|---|---|
| “Canonical reference” | Multiple statements are hardcoded and contradictory | Incorrect authority label |
| XGBoost output is binary | `train_xgboost.py` uses `multi:softprob`, `num_class=5`; predictor returns `window_probabilities` | Factually stale |
| EPSS v3 is current/live | `epss_substitutor.py` loads v4 first, then v3/v2/v1 | Factually stale |
| Training data has 420 columns | Canonical contract is 35 tabular + 384 SBERT = 419 | Factually wrong |
| Calibrator “EXISTS” | File is gitignored and local-only | Environment-specific claim presented globally |
| Fixed samples, metrics, dates and sizes | Much of the narrative is emitted from literal `f.write()` strings | Regeneration does not verify it |

### Root cause

`generators/ml_inventory.py` dynamically inventories files, but most of the
meaningful model narrative is hardcoded. The output timestamp therefore means
“the generator ran now,” not “these claims were verified now.”

### Required implementation

Refactor the generator into two stages:

1. build a structured inventory object containing values, source locations,
   provenance class, and warnings; and
2. render Markdown exclusively from that object.

Values should be derived as follows:

- **Canonical tabular names:** import or statically parse
  `backend/pipeline/config/feature_names.py` and use
  `TABULAR_FEATURE_ORDER`.
- **Embedding dimensions:** derive from canonical feature metadata or encoder
  configuration. If not safely derivable, report unknown.
- **Total input dimensions:** calculate from derived tabular and embedding
  dimensions; never write a second literal total.
- **Training objective and class count:** parse the active training
  configuration from `train_xgboost.py`, or move these values to an explicit
  tracked model manifest consumed by both code and Graphify.
- **Inference output shape:** derive from predictor return keys and model
  objective metadata. The current output should describe exploitation
  probability plus five window probabilities, not a binary-only model.
- **Active XGBoost version:** read the tracked `model_registry.json`, validate
  that `active_version` exists in `versions`, and label invalid registries as an
  error.
- **EPSS active/preferred version:** derive the loader order from a shared
  constant or explicit registry. Do not infer “active” merely from which local
  files happen to exist. Report both preferred version and locally loaded/
  available versions where useful.
- **Metrics and training date:** read tracked registry/metadata. If absent,
  report unknown. Do not preserve a literal ROC-AUC or date in generator code.
- **NPZ dimensions:** when the file is present locally, inspect it with
  `numpy.load(..., allow_pickle=False)` and label the result observed/local.
  When absent, use tracked metadata only if an explicit manifest provides it.
- **Pickled artifacts:** do not unpickle model files merely to generate
  documentation. Unpickling is executable and unsafe for untrusted artifacts.
  Presence, filename, byte size and git tracking status can be inspected safely.
- **Artifact status:** split the table into tracked project artifacts and local
  generated artifacts. Include `tracked`, `ignored`, `missing`, or `local-only`.

Remove “Canonical reference” until the acceptance criteria in this report pass.
A suitable interim label is “Generated discovery inventory; verify model
behaviour against code and tests.”

## Finding 2 — Feature parity confirms counts, not full positional parity

### Verified defects

The regenerated report correctly classifies 35 model inputs and 11 metadata
fields. This is an improvement. However, it then reports:

- counts match; and
- 21 column-by-column mismatches remain.

The report explains those mismatches as heuristic expression-name limitations.
That means the positional analysis is inconclusive, not passing.

### Root cause

`generators/feature_parity.py` reduces AST expressions to names such as
`float()`, `get()`, and `int()`. Those strings cannot establish which canonical
feature occupies a position. It also parses feature names back out of generated
English in `ml_inventory.md`, creating an unnecessary generated-output-to-
generated-output dependency.

### Required implementation

- Treat `TABULAR_FEATURE_ORDER` as the canonical ordered contract.
- Compare every code path to that ordered list, not to prose in
  `ml_inventory.md`.
- Prefer detecting imports/use of the canonical constant over reconstructing
  names from arbitrary expressions.
- Where builders are deterministic and safe to import, call the same real
  builders used by `backend/tests/test_feature_contract.py` with a distinctive
  fixture and compare exact positions.
- If runtime imports are undesirable, create a machine-readable contract result
  from the deterministic contract tests and have Graphify render it.
- Remove the inventory-prose parser.
- Report three independent statuses:
  1. feature count,
  2. exact ordered-name contract, and
  3. distinctive-value positional contract.
- A count match must not produce an overall pass when ordered or positional
  checks are inconclusive.
- Exit non-zero in strict/check mode when a required contract fails or cannot be
  evaluated.

The authoritative enforcement remains the deterministic tests. Graphify should
summarise their contract, not create a weaker competing definition.

## Finding 3 — Knowledge graph loses provenance and mixes synthetic facts

### Verified defects

`knowledge_graph.json` has global source flags but no source/provenance field on
individual nodes or edges. The generator merges:

- local SQLite vulnerability rows;
- known hostname tags parsed from source;
- NVD cache data when present; and
- hardcoded synthetic demo CVEs.

The deduplication algorithm keeps the first node with an ID. It does not merge
properties or provenance. Consequently, source order can decide which facts
survive, and consumers cannot determine whether a specific relationship was
observed or synthetic.

### Required implementation

- Add provenance to every node and edge. At minimum include:
  - `source_type`: `database`, `tracked_source`, `cache`, or `synthetic_fixture`;
  - `source_ref`: relative file/table/fixture identifier;
  - `observed_at` or generation timestamp where appropriate;
  - `synthetic: true|false`.
- Replace first-wins deduplication with deterministic merge behaviour:
  - union provenance entries;
  - merge non-conflicting properties;
  - record property conflicts rather than silently discarding one;
  - sort nodes, edges and provenance deterministically.
- Disable synthetic fallback by default for the canonical output. Expose an
  explicit `--include-synthetic` or `--mode demo` option.
- If a demo graph is needed, generate a distinctly named output such as
  `knowledge_graph.demo.json` or mark the whole graph mode as synthetic-enabled.
- Replace absolute `source_db` with a repository-relative path.
- Add a JSON Schema and increment the schema version when provenance is added.
- Validate all edge endpoints exist and all required provenance fields are
  populated.

## Finding 4 — API dependency output is labelled as a call graph

### Verified defect

`generators/api_deps.py` walks `ast.Import` and `ast.ImportFrom`. Apart from
special handling for router registration, it does not analyse function calls.
“Caller → callee relationships” therefore overstates what it provides.

### Required implementation

Choose one of these explicit scopes:

1. **Recommended:** Rename the output and heading to “Python Import Dependency
   Map,” and describe entries as importer → imported module relationships.
2. Implement a genuine call graph with symbol resolution, aliases, qualified
   names and confidence levels. This is substantially larger and is not needed
   for current TriageMate navigation.

For the recommended import-map scope:

- use “importer” and “imported module,” not caller and callee;
- include all intended package directories recursively rather than only direct
  children of a fixed directory list;
- exclude tests/generated/vendor paths through explicit configuration;
- resolve relative imports correctly;
- include a summary of unresolved or dynamically imported modules;
- add deterministic tests for imports, aliases, relative imports and router
  registration.

The existing filename may remain for backward compatibility, but its title and
description must be accurate.

## Finding 5 — File tree is local, noisy and not reproducible

### Verified defects

The file tree walks the current filesystem and embeds an absolute workstation
path. It may include local untracked content while excluding ignored binary
types through a handwritten extension list. File descriptions are extracted
from first comments and sometimes capture separators or implementation comments
instead of useful summaries.

### Required implementation

- Default committed output to tracked files using `git ls-files`.
- Add an explicit optional local mode if untracked files are useful during
  diagnosis.
- Emit a repository-relative root name, never an absolute path.
- Exclude `graphify_output/` itself or represent it as a single generated
  directory to prevent recursive noise.
- Use module docstrings and Markdown H1 headings for descriptions; if no useful
  description exists, leave it blank rather than using arbitrary comments.
- Make ordering deterministic across operating systems.
- Record mode, TriageMate SHA and dirty state in the header.
- Test symlinks, spaces in paths, ignored files, untracked files and empty
  directories.

## Cross-cutting generator architecture

### Configuration

Replace the hardcoded relative construction of `TRIAGEMATE_DIR` with one of:

- a required/optional `--repo-root` CLI argument;
- an environment variable with validation; or
- robust repository discovery from the current directory.

The command must fail clearly when pointed at the wrong repository. Output paths
should also be explicit rather than discovered by walking for the first folder
named `graphify_output`.

### Structured intermediate data

Each generator should build structured data before rendering. Consider emitting
machine-readable JSON alongside Markdown for the import map, ML inventory and
feature contract. Every derived field should carry:

- value;
- provenance class;
- source reference;
- derivation method;
- warning/error state.

This makes contradictions testable and prevents prose from becoming an
accidental data source.

### Strict mode and exit codes

Add a check mode suitable for CI:

```text
graphify --repo-root <path> --mode tracked-only --strict --check
```

Strict mode should fail on:

- contradictory dimensions;
- invalid active model registry;
- exact feature-order mismatch;
- missing provenance;
- dangling graph edges;
- absolute paths in committed output;
- a generator exception or silently skipped required source;
- output differing from committed generated files.

Warnings about optional local artifacts should not fail tracked-only mode.

### Determinism

Committed outputs should be byte-for-byte reproducible from the same commits.
A wall-clock timestamp prevents that. Either:

- omit timestamps from committed output;
- derive a stable timestamp from `SOURCE_DATE_EPOCH`; or
- exclude generation metadata from the reproducibility comparison.

Sort all dictionaries, nodes, edges, files and dependency entries.

## Required tests

Add generator-level tests in the Graphify repository using small temporary
fixture repositories. Do not depend on the developer’s full TriageMate checkout
for every unit test.

Minimum test matrix:

| Area | Required test |
|---|---|
| ML inventory | Five-class objective is rendered as five-class, not binary |
| ML inventory | Preferred EPSS v4 is derived correctly when v4 is declared but absent locally |
| ML inventory | One canonical dimension calculation appears consistently everywhere |
| ML inventory | Missing artifacts become `missing`/`unknown`, not stale hardcoded claims |
| ML inventory | Ignored local artifacts are visibly labelled local-only |
| Feature parity | Exact 35-name order passes |
| Feature parity | Swapping two names fails despite equal counts |
| Feature parity | Inconclusive AST extraction cannot produce a pass |
| Knowledge graph | Every node and edge has provenance |
| Knowledge graph | Synthetic records are absent by default |
| Knowledge graph | Conflicting duplicate properties are recorded deterministically |
| Knowledge graph | No dangling edge endpoints |
| Import map | Relative imports and aliases resolve as importer/imported relationships |
| File tree | Tracked-only mode excludes untracked and ignored files |
| All outputs | No absolute workstation paths |
| All outputs | Two runs from the same fixture produce identical committed content |

Add a TriageMate integration command, preferably `just graphify-check`, that:

1. runs the generators in tracked-only strict mode;
2. validates schemas and feature contracts;
3. fails if committed output would change; and
4. does not mutate the working tree during check mode.

## Acceptance criteria

The remediation is complete only when all of the following are true:

- [ ] `ml_inventory.md` no longer labels itself canonical unless all rendered
      behavioural claims are derived or explicitly declared.
- [ ] No binary-output claim remains for the five-class XGBoost model.
- [ ] EPSS v4 is represented as the preferred current model; local absence is
      reported separately and does not rewrite project status to v3.
- [ ] The XGBoost total is calculated once and is 419 everywhere for the current
      contract.
- [ ] No model metric, training date, threshold or active version is duplicated
      as handwritten generator prose.
- [ ] Local ignored artifacts are distinguishable from tracked project state.
- [ ] Feature parity reports exact ordered and positional results, not only equal
      counts.
- [ ] An equal-count/order-mismatch fixture fails strict mode.
- [ ] Every knowledge-graph node and edge carries provenance.
- [ ] Synthetic graph data is opt-in and visibly labelled.
- [ ] Import-map terminology no longer claims function-call analysis.
- [ ] The committed file tree contains no absolute path and defaults to tracked
      files.
- [ ] Generator tests pass.
- [ ] TriageMate’s deterministic feature-contract tests pass.
- [ ] `just graphify-check` passes from a clean checkout without local model or
      data artifacts.
- [ ] Regeneration produces no unexplained diff on a second run.
- [ ] `docs/INDEX.md` and `AGENTS.md` accurately describe the authority and
      limitations of each output.
- [ ] A mandatory bookkeeper freshness pass reports clean after regeneration.

## Recommended implementation sequence

### Phase 0 — Baseline and protect unrelated work

1. Inspect `git status` in both repositories.
2. Record current output hashes and the confirmed defects above.
3. Add failing fixture tests for the known defects before changing generators.
4. Do not include existing unrelated TriageMate Graphify-output modifications
   in PR #48 or Sprint 26b.

### Phase 1 — Shared metadata and reproducibility

1. Add explicit repo-root/output CLI configuration.
2. Add shared generation metadata and provenance types.
3. Add deterministic tracked-only mode.
4. Establish JSON schemas/structured intermediate representations.

### Phase 2 — Correct semantic generators

1. Refactor `ml_inventory.py` to derive facts and report unknowns.
2. Replace heuristic parity passing with exact canonical-contract checks.
3. Add per-record graph provenance and synthetic opt-in.

### Phase 3 — Correct descriptive generators

1. Relabel `api_deps.md` as an import dependency map.
2. Make the file tree tracked-only, relative and deterministic.

### Phase 4 — Integrate and verify

1. Run all Graphify unit tests.
2. Regenerate TriageMate outputs in tracked-only mode.
3. Run TriageMate feature-contract tests and the full relevant gate.
4. Run strict generation twice and confirm the second run is clean.
5. Update `docs/INDEX.md` and `AGENTS.md` authority wording.
6. Delegate to bookkeeper for the mandatory freshness pass and resolve any real
   drift before completion.

## Non-goals

- Do not retrain models merely to fix documentation generation.
- Do not commit large `.pkl`, `.npz`, cache or corpus files.
- Do not hand-edit generated output to conceal a generator defect.
- Do not build a full static call graph unless there is a demonstrated consumer;
  accurate import-map terminology is sufficient.
- Do not block tracked-only generation because optional local artifacts are
  absent.

## Handoff warning

The central trap is fixing `graphify_output/*.md` instead of the sibling
Graphify generators. Any direct output correction will be overwritten on the
next `just graphify` run. Begin with failing tests in the Graphify repository,
fix the generators there, then regenerate and validate TriageMate outputs.
