# @clearproof/cli

Command-line tool for generating and verifying ZK compliance proofs.

## Development status

The 0.4.0 checkout is unreleased and requires repository access. The public
0.3.0 CLI has an unavailable `@clearproof/content` dependency; a public install
is not currently a working quickstart. Use an authorized source checkout:

```bash
npm install
npm run build
node packages/cli/dist/index.js --help
```

Proof demos require a matching WASM, proving key and verification key. Bundled
artifact availability is not guaranteed in a source checkout. The isolated
`scripts/test_development_circuits.py` workflow generates unapproved development
artifacts; those are not production ceremony material.

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
"case_digests": ["..."] }`. See `docs/internal/PILOT_POLICY_EVALUATION.md` for
schemas, limits, roles and interpretation. Keep the output inside the tenant's
protected workflow. Do not place customer snapshots or tokens in arguments or
plaintext files.

HTTPS is required except literal loopback HTTP for local evaluation. The origin
must have no credentials, path, query or fragment. Redirects are rejected.
Input is limited to 1 MiB/10 seconds; the API request and response share a
30-second deadline and the response is limited to 2 MiB. Errors return exit 1
with a generic diagnostic; no submitted values or response bodies are echoed.
A comparison neither activates a policy nor consumes transfer authorization.

## Links

- [Main repository](https://github.com/repfigit/clearproof)
- [Circuit documentation](https://github.com/repfigit/clearproof/tree/main/packages/circuits)

## License

Apache-2.0

## Investigation reports (unreleased)

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
