# Target-anchored CPG behavior analysis APR

Correctness repair treats the edit location and the reason for the edit as two
different problems. Tree-sitter fixes the exact local edit unit. A deterministic
Joern Behavior Analysis builds a compact, source-bound view of the target before
causal diagnosis begins. The full cached project CPG remains searchable, but it
is not copied into the initial prompt.

1. `FailureContractBuilder` stores source-backed failing test definitions and
   runner output without using log regexes to invent expected behavior.
2. `TargetAnchor` requires one exact tree-sitter function identity and source
   byte range. Missing, stale, or ambiguous targets stop repair; Joern never
   resolves the edit target.
3. `TargetInventory` enumerates target-local source entities for prompt binding
   and exact follow-up query anchors.
4. `BehaviorAnalysis` calls `get_target_behavior_analysis` without an LLM query
   planner. Its initial projection contains only the exact target anchor,
   target calls and their arguments/immediate result uses, target writes,
   source-level parameters and local declarations, and uniquely resolved exact
   callee contracts. Compiler-generated locals are rejected by binding Joern
   facts back to Tree-sitter declaration ranges. Calls are not cut off by a
   positional top-N rule.
5. Behavior output is a structured capsule, not flat source cards. Target
   source appears once; every related source range appears once in
   `source_regions`. Variable declarations/writes/call uses, calls, argument
   mappings, exact callee contracts (parameters, guarded returns, and
   assignments), and evidence IDs refer to those regions.
6. Only Joern facts that map back to a project file and source byte range enter
   the evidence capsule. Related methods use Joern AST coordinates; the edit
   target continues to use the oracle Tree-sitter identity/range. Synthetic/unmappable CPG nodes remain explicit audit
   diagnostics; they do not invalidate the source-backed facts from the same
   analysis. A target census exceeding the configured bound stops with an
   explicit `joern_target_behavior_truncated` error instead of silently dropping
   facts. There is no source scan, regex, or alternate backend fallback.
7. `CausalDiagnosis` forms evidence-cited causal chains from the compact
   projection. A remaining critical proof gap may produce one typed,
   target-bound Joern expansion round through `get_behavior_evidence` for an
   exact callee contract, sibling implementation, caller result use,
   type/constant definition, or deeper dataflow. Overload candidates and
   unresolved callees are never presented as contracts. A malformed optional
   need is recorded as a diagnostic and cannot discard an otherwise valid
   causal hypothesis.
8. `HypothesisAdjudicator` emits at most three plans. Plans are enriched with
   any available cited evidence but are not rejected by target, evidence,
   source-anchor, or semantic validation rules before execution.
9. `PatchSynthesizer` receives one plan, its available cited evidence, the
   failure contract, and the exact replacement unit. Every non-empty response
   is inserted at the persisted target byte range without a Patch Validation
   or AST-shape gate, then sent to real build/test validation.
10. Build and test results are the adjudicator. Compile errors refine synthesis;
   unchanged failures trigger a new behavior/causal search that receives the
   tested diff, prior mechanism, plan, and validation transition as negative
   evidence; partial fixes or
   regressions trigger a preservation-focused behavior/causal search; plausible
   candidates remain in the portfolio.

LLM calls are stateless. `repair_state` persists the target inventory,
deterministic behavior analysis, optional follow-up needs, Joern query rounds, source-backed evidence, hypotheses,
plans, validation feedback, and errors. Each round reconstructs its prompt from
this compact state rather than relying on provider session memory.

The search domain is the full Joern CPG. The initial prompt contains only
source-bound call and variable contracts; every wider relation must be requested
as an explicit, hypothesis-bound follow-up need.
