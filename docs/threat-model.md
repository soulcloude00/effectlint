# Threat model

effectlint asks one narrow question: did a proposed configuration introduce a new effect or widen authority?

## In scope

New process, network, secret-reference, OAuth scope, token audience, deployment identity, approval-bypass, and instruction-like tool metadata authority. Baseline comparison is exact and deterministic.

## Out of scope

Runtime containment, authorization enforcement, semantic code review, compromised build infrastructure, malicious parsers, and proving that a deployment is safe. A clean report means only that no modeled authority delta was found.

## Trust boundaries

Configuration and tool descriptions are untrusted input. Output may expose key names, identities, scopes, and endpoints, but never secret values. Review SARIF and BOM artifacts before publishing them from private repositories.
