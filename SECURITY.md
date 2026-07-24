# Security Policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately through the repository's
[GitHub Security Advisories](https://github.com/chinmay-sawant/codehound/security/advisories/new).
Do not open a public issue for an unpatched security vulnerability.

Include a clear reproduction, affected CodeHound version or commit, expected
and observed behavior, and any suggested mitigation. We will acknowledge a
report within **5 business days** and aim to provide a remediation plan within
**14 days**. We ask reporters to keep unfixed issues under embargo until a
fix or coordinated disclosure date is agreed.

## Supported versions

Security fixes are applied to the latest release on the default branch.
Older releases are supported only when a backport is explicitly announced in
the corresponding advisory or release notes.

## Scope

Reports covering CodeHound's Rust implementation, release artifacts, GitHub
Actions workflows, and shipped rules are in scope. Detector false negatives
and false positives are welcome; please include a minimal source example and
the command used to scan it.

## Product honesty

CodeHound's taint tracking is **experimental** and name-string based — not
security-grade gating (see README). Reports that clarify where heuristics
over-claim or under-report are especially useful.
