# Hash Validation Registry

This repository publishes factual cryptographic integrity data only.

## Purpose

The contents allow independent parties to:

- verify external artifacts against published checksums;
- check consistency between independently obtained copies;
- validate authenticity only when a detached signature is verified with a separately trusted public key.

No original artifacts are stored or distributed through this repository.

## Scope

This repository may contain checksum files and detached cryptographic signatures. It does not contain source data, binaries, personal data, configuration files, or operational context.

## Verification

Verify a checksum list with:

```bash
sha256sum -c <checksum-file>
```

If a detached signature is present, verify it with the documented algorithm and a public key obtained through an independently trusted channel. A checksum alone proves integrity, not publisher identity.

## Notes

- This repository is a publication reference only.
- It does not imply availability, completeness, authenticity, or suitability of any external artifact.

_No license is granted. This repository publishes factual integrity data only and provides no warranty of any kind._
