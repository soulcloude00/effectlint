# Contributing

Thanks for helping make agent authority easier to review.

## Development

```sh
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all
```

Add a small fixture for every scanner or rule change. Tests should assert both what is detected and what must not be reported. Never put real tokens, account IDs, or private configuration in fixtures.

## Pull requests

Keep changes focused and explain the authority change the PR detects. New work is developed in draft pull requests; maintainers decide when to merge. Do not claim adoption, users, or security guarantees without evidence.

## Security reports

Please use GitHub's private security-advisory flow for vulnerabilities. Do not open a public issue containing exploit details or secrets.
