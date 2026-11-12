# @clearproof/cli

Command-line tool for Clearproof. Nothing here is audited, and no production proving keys exist.

| Commands | Profile | What they do |
| --- | --- | --- |
| `inspect-current`, `authorize-current`, `observation`, `policy diff`, `investigation`, `counterparty` | Current pilot (`pilot-transfer-v3`, 8 public signals) | Call an authenticated Clearproof API that an operator runs. The CLI does not generate or verify pilot proofs itself. |
| `doctor`, `verify-history` | Current pilot | Review local files offline. `doctor` needs a source checkout (below). |
| `prove`, `verify`, `demo` | Legacy demo (16 public signals) | Generate and verify proofs locally with snarkjs, using legacy artifacts you supply. Not the current profile. |
| `help`, `recipes`, `explain`, `report` | Both | Documentation, recipes and a pre-filled issue link. |

## Install

```bash
npm install -g @clearproof/cli
clearproof --help
```

Or build from a source checkout:

```bash
npm ci
npm run build
node packages/cli/dist/index.js --help
```

## Legacy demo commands

`prove`, `verify` and `demo` work on the legacy 16-signal profile only. They
require a matching WASM, proving key and verification key. No npm package
supplies them. Generate unapproved development artifacts with the isolated
`scripts/test_development_circuits.py <new-directory>` workflow from a source
checkout, then run `clearproof demo --artifacts <new-directory>/legacy`. They are
not production ceremony material. A legacy proof is not a `pilot-transfer-v3`
authorization.

## Artifact doctor

`doctor` works only from a source checkout. `--python` is required and must be
the Python executable of that checkout's environment, because the command runs
the `src.prover.pilot_artifacts` module with it. Run it from the checkout root.
An npm-only install has no such module, and the command then reports
`doctor_configuration_or_runtime_failed`.

Inspect local pilot files using an independently reviewed manifest pin:

```bash
node packages/cli/dist/index.js doctor --python .venv/bin/python \
  --artifacts /path/to/pilot-artifacts \
  --trusted-manifest-digest APPROVED_LOCAL_DEVELOPMENT_MANIFEST_DIGEST
```

Exit 0 means the pinned development files match; `production_eligible` remains
false. Add `--mode production` to check production eligibility: every supported
manifest currently rejects with exit 1. Profile and policy-schema support are
reported separately. The command never downloads, proves, publishes or consumes
an authorization. It bounds runtime/output,
and omits paths and file contents from diagnostics. See the
[artifact guide](https://github.com/repfigit/clearproof/blob/main/docs/internal/PILOT_ARTIFACT_DOCTOR.md) for trust and
historical-profile limits. A bundle's own claimed pin is not independent approval.

## Policy comparison

`policy diff` calls the authenticated Python API; it does not duplicate policy
semantics in JavaScript. Provide an operator-selected API origin and provision
`CLEARPROOF_API_TOKEN` in the environment through your secret manager. The token
needs `policy:read` and `evidence:decrypt`. Input is read from stdin and the
counterfactual JSON report is written to stdout.

```bash
# Pipe comparison JSON from an authorized encrypted source into this command:
node packages/cli/dist/index.js policy diff --api-url https://your-api.example

# Use retained before/after policy digests and case digests as the stdin payload:
node packages/cli/dist/index.js policy diff --api-url https://your-api.example --stored
```

The default input is `{ "before": ..., "after": ..., "cases": [...] }`.
With `--stored`, it is `{ "before_digest": "...", "after_digest": "...",
"case_digests": ["..."] }`. See the [policy evaluation guide](https://github.com/repfigit/clearproof/blob/main/docs/internal/PILOT_POLICY_EVALUATION.md) for
schemas, limits, roles and interpretation. Keep the output inside the tenant's
protected workflow. Do not place customer snapshots or tokens in arguments or
plaintext files.

HTTPS is required except literal loopback HTTP for local evaluation. The origin
must have no credentials, path, query or fragment. Redirects are rejected.
Input is limited to 1 MiB/10 seconds; the API request and response share a
30-second deadline and the response is limited to 2 MiB. Errors return exit 1
with a generic diagnostic; no submitted values or response bodies are echoed.
A comparison neither activates a policy nor consumes transfer authorization.

## Investigation reports

The `investigation timeline` and `investigation queue` commands read JSON from
stdin and use the same explicit API origin and environment token as policy
comparison. The token needs `evidence:read` and `evidence:decrypt`.

```bash
# Pipe a TransferScope object into the timeline command:
node packages/cli/dist/index.js investigation timeline --api-url https://your-api.example

# Pipe QueueRequest JSON, such as {}, into the queue command:
node packages/cli/dist/index.js investigation queue --api-url https://your-api.example --pages 8
```

Both default to readable text; `--json` emits the report. Timeline text displays
independent states, findings and source/receipt times. It does not infer
settlement from compliance approval. Output belongs in protected tenant workflows.

Queue collection follows continuation through empty filtered pages, rejects
nonadvancing cursors and duplicate transfer scopes, and sorts the collected
results by reported age. `--pages` defaults to 1 and permits 1–32. The collection
has a 60-second deadline; each HTTP request retains its 30-second bound. A page
budget exhausted before the final page produces an explicitly partial report
with `next_cursor`; pass that digest as `after` in the next stdin request.
Starting from a cursor is also marked partial relative to the whole queue.
Pages have separate observation times and are not a frozen historical snapshot.
Terminal-control characters in rendered fields reject instead of being executed.

## Recipes

`clearproof recipes` lists the recipes and `clearproof recipes <name>` prints one.
Nothing is executed unless you add `--run`. With `--run`, the CLI shows each
step and asks before running it. All steps of a recipe run in one `bash` session
started in the current directory, so a `cd` or `export` in one step still
applies to the next; the recipes expect the root of a source checkout. Each step
is limited to 60 seconds and is killed, with everything it started, when the
limit passes. Steps cannot read from the terminal, so commands that ask for
typed confirmation are documented in the recipe for you to run yourself. After a
failed step the CLI asks whether to continue. `--run` requires `bash`.

Most recipes cover the legacy 16-signal demo path and say so at the top.

## Links

- [Main repository](https://github.com/repfigit/clearproof)
- [Circuit documentation](https://github.com/repfigit/clearproof/tree/main/packages/circuits)

## License

Apache-2.0
