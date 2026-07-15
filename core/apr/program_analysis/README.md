# Joern setup

## Correctness target and evidence contract

Correctness repair is AST-first. A source target is identified by source path,
qualified/scoped name, signature, byte/line range and AST hash. Joern enriches
that identity with control/data-flow facts; it must not silently replace the
source target or choose a top-scoring overload.

When Tree-sitter finds multiple definitions, correctness repair requires an
exact signature/source/oracle discriminator. Otherwise it writes an ambiguous
target artifact and stops that target; it does not queue overload alternatives
or construct a coordinated patch.

Correctness evidence begins with deterministic `get_target_behavior_analysis`.
It enumerates calls, variables, assignments, branches, returns, resolved
callees, exact caller result uses, types, and control/data-flow from the exact
target method. Only a proof gap after causal diagnosis can invoke
`get_behavior_evidence` for one target-bound expansion round. Only source-backed
results enter the prompt.

Behavior Analysis materializes a non-duplicating capsule: exact target source
is stored once, related source ranges are deduplicated in `source_regions`, and
calls/variables/branches/returns/contracts refer to source and evidence IDs.
Correctness repair always sets `allow_source_scan_fallback=False`. An unavailable
engine, an unresolved exact target method, or no source-backed behavior facts is
a hard error. Individual synthetic/unmappable Joern nodes are retained as audit
diagnostics while valid source-backed facts continue. Other APR routes may
retain their own fallback policies.

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
python3 -c "from core.apr.program_analysis import joern_available; print(joern_available())"
```

APR uses Joern by default. Correctness behavior search requires it and records
an error when it is unavailable; no tree-sitter/source-scan evidence fallback
is used for semantic contracts.

Correctness follow-up query regions receive exact absolute source spans from
the target inventory rather than independently re-numbering CPG nodes.
Joern analysis-method binding receives the full scoped name, source signature,
and source start line; leaf names are used only to seed candidates. This binding
never replaces the Tree-sitter edit target.
