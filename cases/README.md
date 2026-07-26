# Diagnostic case submissions

A diagnostic case is a sanitized, reviewed record of a real failure and its
evidence-backed resolution. Cases are reference material. They do not add new
rules automatically and similarity never proves that two failures share a cause.

## Required process

1. Reproduce the problem with public or fabricated inputs.
2. Remove credentials, private project data, local usernames, and unnecessary
   identifiers.
3. Validate the record against [`schema.json`](schema.json).
4. Open a pull request with the original source or reproduction steps.
5. Have a maintainer other than the submitter verify the evidence and resolution.
6. Set `review.status` to `reviewed` only after that review.

Distributed indexes may contain only reviewed cases. Duplicate cases, reports
without a reproducible source, and generated fixes are not accepted.

## Compatibility

Each record names the Arc chain ID and the Arc Doctor, ruleset, or dependency
versions for which it was verified. If later network behavior contradicts a
case, mark it superseded rather than rewriting its historical evidence.

The repository intentionally has no semantic index until a useful reviewed case
corpus and evaluation set exist.
