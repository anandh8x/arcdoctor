# Reports and redaction

Every Arc Doctor diagnosis can be printed as terminal text or JSON. JSON reports
use schema version 1 and include:

- the collection time
- Arc Doctor and ruleset versions
- public network evidence
- diagnosis-specific evidence
- stable findings with confidence and rule versions
- a `sanitized` marker

The schema is available at
[`schema/report-v1.schema.json`](../schema/report-v1.schema.json).

Create a JSON report:

```bash
arcdoctor inspect 0xTRANSACTION_HASH --json > report.json
```

Sanitize and re-export an existing report:

```bash
arcdoctor report report.json --output shared-report.json
```

Use `--format text` for a human-readable export. Existing output files are not
replaced unless `--force` is supplied. Files created by the report command use
owner-only permissions.

## Safety boundary

Arc Doctor redacts authenticated URL credentials, sensitive query values,
context-labelled private keys, seed phrases, bearer tokens, common secret
assignments, usernames in home-directory paths, terminal escape sequences, and
invalid control characters.

Redaction is a safety measure, not a guarantee. Review every report before
sharing it. Never provide Arc Doctor with a private key, seed phrase, password,
wallet keystore, or complete environment file.

Public transaction hashes, addresses, selectors, bytecode hashes, error names,
and Arc network identity remain visible because they are diagnostic evidence.
