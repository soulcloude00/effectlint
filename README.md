# effectlint

**Make authority changes in agent systems visible in code review.**

effectlint scans agent and deployment configuration into a versioned **Capability BOM**. Its GitHub Action will compare the base and head BOMs and annotate a pull request with only newly introduced effects or widened authority.

This helps reviewers catch changes that ordinary dependency and secret scanners miss:

- new MCP servers and tools
- widened OAuth scopes
- new shell or network reach
- deployment identity or cloud-account changes
- removed human-approval boundaries
- confused-deputy and audience-mismatch risks

The first release intentionally does **not** include an enforcement proxy. effectlint is a static release gate: reviewable evidence, JSON/SARIF output, and CI policy.

## What works today

The Rust CLI scans an MCP JSON configuration end-to-end. For each server it records process-spawn authority, URL-shaped network endpoints in arguments, and references to sensitive environment variables. It emits a versioned JSON Capability BOM or SARIF 2.1.0.

```sh
cargo run -- tests/fixtures/mcp.json
cargo run -- tests/fixtures/mcp.json --format sarif
```

Example capability:

```json
{
  "server": "github",
  "effect": "secret.read",
  "authority": "GITHUB_TOKEN",
  "evidence": "env key: GITHUB_TOKEN"
}
```

Values are never included in the output, only environment-variable names.

## Direction

1. Compare base/head BOMs and report only new authority, with conformance fixtures for scope expansion and approval removal.
2. Add scanners for OAuth manifests and common agent/deployment formats, plus fixtures for confused deputy, audience mismatch, tool poisoning, and foreign cloud identities.
3. Ship the TypeScript GitHub Action with PR annotations, SARIF upload, configuration, and release packaging.

## Security model

effectlint is evidence for reviewers, not a proof that a system is safe. Generated findings should be reviewed alongside runtime controls, identity policy, and application code.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Please report security issues privately using GitHub's security-advisory flow rather than opening a public issue.

## License

Apache License 2.0. See [LICENSE](LICENSE).
