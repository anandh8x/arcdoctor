# Security

Arc Doctor is a diagnostic tool, not a smart contract auditor. Its output must
not be treated as proof that a contract, transaction, or deployment is safe.

## Reporting a vulnerability

Please report vulnerabilities through the repository's private GitHub security
advisory form. Do not open a public issue containing an unpatched vulnerability,
credentials, private project data, or a report that may contain secrets.

Include the affected version, a minimal reproduction, and the security impact.
Use fabricated credentials and public testnet data whenever possible.

## Sensitive data

Arc Doctor is read-only and never needs a private key, seed phrase, keystore
password, or wallet connection. Never provide those values to Arc Doctor, an
issue, a diagnostic case, or another community member.

Report sanitization covers known secret patterns, authenticated URLs, terminal
control sequences, and local usernames. It is a safety measure, not a guarantee.
Always review an exported report before sharing it.
