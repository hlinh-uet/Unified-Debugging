# Shared program analysis providers

This package is the common static-analysis substrate used by FailContext, FL,
correctness APR, and security APR.  It owns Tree-sitter parsing, Clang semantic
resolution, Joern/CPG queries, source-scan fallback, and policy-free evidence
contracts.  It does not choose suspicious functions or repair actions; those
decisions remain in the FL and APR controllers.

The historical `core.apr.program_analysis` and correctness
`clang_semantic_provider` modules are compatibility aliases to these same
module objects.  They do not create duplicate providers or caches.

## Correctness target and evidence contract

Correctness repair is AST-first. A source target is identified by source path,
qualified/scoped name, signature, byte/line range and AST hash. Initial evidence
is also Tree-sitter-only. Joern may enrich a later explicit proof gap; it must
not silently replace the source target or choose a top-scoring overload.

When Tree-sitter finds multiple definitions, correctness repair requires an
exact signature/source/oracle discriminator. Otherwise it writes an ambiguous
target artifact and stops that target; it does not queue overload alternatives
or construct a coordinated patch.

Correctness evidence begins with a complete target-local SyntaxIR produced by
declarative Tree-sitter queries. A balanced budgeted view is exposed to the LLM;
records outside that view remain in the retrieval index. SyntaxIR contains
syntax anchors only and does not
infer def/use, types, overloads, external writes, or callee contracts. A second
layer invokes Clang with the target command from `compile_commands.json`; only
that compiler result may add canonical types and resolved direct-call identities.
If compiler context is unavailable, evidence remains explicitly syntax-only.
Initial evidence never invokes Joern or enumerates callers/full callee bodies.
Only a proof gap after causal diagnosis can invoke `get_behavior_evidence` for
one target-bound expansion round. Compiler-resolved declaration retrieval runs
first under fixed query/region/character budgets. Joern queries the full cached
CPG only for unanswered needs: need-local symbols and relation families control
traversal and ranking, while the subject source range serves as an anchor instead
of truncating project-wide uses. Only source-backed results enter the prompt.

Behavior Analysis materializes a non-duplicating capsule: exact target source
is stored once, related source ranges are deduplicated in `source_regions`, and
calls/variables/branches/returns/contracts refer to source and evidence IDs.
Structural initial evidence has no regex fallback. Missing grammars, parse
failures, compilation databases, compile commands, or compiler ASTs are
reported as degraded/unresolved rather than replaced by name/arity guesses.
Follow-up Joern nodes retain their existing source-backing and audit
requirements. Other APR routes may retain their own fallback policies.

Joern is not a Python package, so nothing needs to be added to
`requirements.txt`.

Install Joern:

```bash
mkdir -p ~/tools/joern
cd ~/tools/joern
curl -L "https://github.com/joernio/joern/releases/latest/download/joern-install.sh" -o joern-install.sh
chmod u+x joern-install.sh
./joern-install.sh --interactive
```

Check that Joern is available:

```bash
which joern
which joern-parse
```

If APR cannot find the binaries, set them manually:

```bash
export APR_JOERN_BIN="$HOME/bin/joern/joern-cli/joern"
export APR_JOERN_PARSE_BIN="$HOME/bin/joern/joern-cli/joern-parse"
```

Run a quick check:

```bash
python3 -c "from core.program_analysis import joern_available; print(joern_available())"
```

Correctness repair does not use Joern on the initial path. Joern is optional for
later hypothesis-bound expansion; its absence does not invalidate SyntaxIR or
Clang semantic evidence.

Correctness follow-up query regions receive exact absolute source spans from
the target inventory rather than independently re-numbering CPG nodes.
Joern analysis-method binding receives the full scoped name, source signature,
and source start line; leaf names are used only to seed candidates. This binding
never replaces the Tree-sitter edit target.
