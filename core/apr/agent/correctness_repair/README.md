# Target-anchored compact behavior analysis APR

Correctness repair treats the edit location and the reason for the edit as two
different problems. Tree-sitter fixes the exact local edit unit and builds the
small source-bound evidence view used before causal diagnosis. Joern is not on
the initial path; the full cached project CPG remains available only for an
explicit hypothesis-driven follow-up.

1. `FailureContractBuilder` resolves the runner-reported source line to the exact
   failing assertion, extracts a bounded backward local def/use slice for that
   test scenario, and emits an explicit proof obligation. Runner observations
   remain separate from assertion operands. If a signal or assertion has no
   unique source location, it does not infer a crash location from test order;
   ambiguous assertion candidates are explicitly labeled uncertain rather than
   promoted to facts. The complete test body is retained only long enough to
   build this focused contract and is not copied into the LLM prompt.
2. `TargetAnchor` requires one exact tree-sitter function identity and source
   byte range. Missing, stale, or ambiguous targets stop repair; Joern never
   resolves the edit target.
3. `TargetInventory` runs declarative Tree-sitter Query packs inside the exact
   target and emits a complete target-local SyntaxIR: parameters, declarations, calls and
   arguments, assignments, updates, returns, and control predicates with exact
   byte/line ranges. This layer makes no def/use, type, overload, ownership, or
   external-write claim. Isolated replacement-unit parsing is a diagnosed
   fallback for macro/template-heavy source.
4. `BehaviorAnalysis` retains every SyntaxIR record in the retrieval index and
   exposes a balanced, source-spanning view (by default at most 31 records plus
   the target) to the LLM. The view includes every available syntax kind before
   distributing remaining slots proportionally, so assignments and updates are
   not categorically discarded. It asks Clang for semantic deltas using
   the target translation unit from `compile_commands.json`. Only compiler
   results may add canonical variable types or resolved direct-call identities
   and signatures. This initial stage never invokes Joern.
5. Behavior output is a structured capsule, not flat source cards. Target
   source appears once; every related source range appears once in
   `source_regions`. Syntax records and compiler-resolved calls/types refer to
   those regions. Syntax-only records remain explicitly labeled and are never
   promoted to semantic facts by name/arity matching.
6. The semantic provider uses the project compilation database and the Clang
   frontend AST. If the database, matching command, compiler, or target AST is
   unavailable, the run degrades to syntax-only evidence with a diagnostic; it
   does not scan source files or guess a callee contract. The provider boundary
   is intentionally small so clangd index lookup can replace the frontend
   implementation later without changing SyntaxIR or the LLM-facing capsule.
7. `CausalDiagnosis` forms evidence-cited causal chains from the compact
   projection. A remaining critical proof gap produces a typed, target-bound
   request. Compiler-backed retrieval runs first for resolved callee contracts,
   overloads, and type/enum/template definitions, with a default budget of three
   compiler queries, five source regions, 2,400 total source characters, and 800
   characters per region. Only unanswered static needs fall through to Joern for
   callers, sibling implementations, or deeper dataflow. Each need is queried
   and linked independently.
   Follow-up needs pass through one canonical normalizer before retrieval.
   LLM-visible call/evidence aliases are resolved back to SyntaxIR entities;
   declaration or target-wide anchors are rebound to a unique matching call
   when possible. Relation-specific symbol binding may drop unrelated symbols
   without discarding the need, and the executable-query budget is applied only
   after normalization and priority ranking. Only malformed, unsupported, or
   genuinely unresolvable source bindings are rejected.
   The subject range is the query anchor, not a boundary on project-wide value
   uses or caller/callee traversal. Ambiguous overloads are explicitly labeled
   as candidates rather than presented as exact contracts. A malformed optional
   need is recorded as a diagnostic and cannot discard an otherwise valid
   causal hypothesis. All Joern, CPG, and Tree-sitter retrieval is explicitly
   labeled `static_program_semantics`: it can answer definitions, contracts,
   possible branches, source argument expressions, and static data-flow, but
   never a concrete value, branch taken, or return observed in the failing run.
   Runtime-specific needs are not sent to Joern and remain
   `requires_runtime_evidence`. A causal hypothesis supported only by static
   evidence cannot retain runtime-observed/high-confidence status.
8. `HypothesisAdjudicator` emits at most three plans. Plans are enriched with
   any available cited evidence but are not rejected by target, evidence,
   source-anchor, or semantic validation rules before execution. Plans are
   attempted in rank order and execution stops at the first plausible patch.
9. `PatchSynthesizer` receives one plan, its available cited evidence, the
   failure contract, and the exact replacement unit. Every non-empty response
   is inserted at the persisted target byte range without a Patch Validation
   or AST-shape gate, then sent to real build/test validation.
10. Build and test results are the adjudicator. ReFix first preserves the lineage
   of the best validated Fix candidate: it receives that exact failed patch, the
   plan that produced it, and typed validation feedback. It does not replace the
   selected plan with the first result of a new diagnosis. Compile errors refine
   synthesis, partial fixes or regressions refine preservation, and unchanged
   failures request a more faithful implementation of the selected mechanism.
   A plausible candidate terminates the remaining plan portfolio and is persisted.

LLM calls are stateless. `repair_state` persists the target inventory,
deterministic behavior analysis, optional follow-up needs, optional Joern query rounds, source-backed evidence, hypotheses,
plans, validation feedback, and errors. Each round reconstructs its prompt from
this compact state rather than relying on provider session memory.

The sandbox adapter materializes the analysis compilation database before
correctness planning. Codeflaws records the same GCC fallback command used by
validation. Metadata/container builds clean persistent build state before the
export build so an old CMake cache cannot suppress
`CMAKE_EXPORT_COMPILE_COMMANDS`; failed exports are not negatively cached.
The resulting commands remap source and
include paths to the immutable buggy worktree while retaining generated-build
paths. If `bear` exists in the build container it captures non-CMake compiler
invocations as well; otherwise those builds degrade explicitly when they do not
produce a database. Existing project databases are reused. `APR_COMPILE_COMMANDS` may still
point to another file/directory, and `APR_CLANG_BIN` may select Clang. These are
runtime tool inputs, not Python dependencies; no regex/source-scan fallback is
enabled when they are absent.

The initial search domain is a budgeted LLM view over the exact target's full
SyntaxIR index plus available compiler semantic deltas. Records outside the view
remain available to hypothesis-driven retrieval. No project-wide Tree-sitter source index, regex
resolver, or Joern traversal runs initially. Every wider relation must be
requested as an explicit, hypothesis-bound follow-up need. Follow-up diagnostics
separately report compiler retrieval and its budget, raw CPG results,
source-mapped facts, and facts linked to each need.
