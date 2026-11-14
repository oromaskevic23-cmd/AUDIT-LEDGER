<p align="center"><img src="assets/branding/banner.svg" alt="AUDIT LEDGER — Evidence & Accountability Infrastructure" width="100%"/></p>

# AUDIT LEDGER

**Evidence & Accountability Infrastructure · IMPERIAL Core**

*Every action leaves evidence.*

Hash-chained synthetic event records and Ed25519-signed checkpoints with independent verification of exact length and terminal digest.

**Status: LOCAL TESTED REFERENCE / INDEPENDENT QA PENDING.** No production deployment, certification or real Owner enrollment is claimed.

## Quick start

Node.js 22+; no external dependencies or paid services.

```sh
npm test
```

API: `append(entries, event); checkpoint(entries, privateKey); verifyLedger(entries, receipt, publicKey)`.

- [Architecture and release gates](ARCHITECTURE.md)
- [Threat model](THREAT_MODEL.md)
- [Security policy](SECURITY.md)
- [Source](src/index.mjs) · [Tests](test/reference.test.mjs) · [Local test evidence](evidence/LOCAL_TEST_EVIDENCE.md)
- [Authorship](AUTHORS.md) · [Roadmap](ROADMAP.md)

## Limitations

No persistent append-only store, external witness, Merkle inclusion proofs, trusted timestamp, tenant authorization or production immutability. A trusted externally retained checkpoint is necessary to detect history replacement.

## Related components

[ZERO TRUST](https://github.com/oromaskevic23-cmd/ZERO-TRUST) · [GUARDIAN CORE](https://github.com/oromaskevic23-cmd/GUARDIAN-CORE) · [APPROVAL GATEWAY](https://github.com/oromaskevic23-cmd/APPROVAL-GATEWAY) · [AUDIT LEDGER](https://github.com/oromaskevic23-cmd/AUDIT-LEDGER) · [CYBER HAK](https://github.com/oromaskevic23-cmd/CYBER-HAK-Public)

## Founder and authorship

<p align="center"><img src="https://raw.githubusercontent.com/oromaskevic23-cmd/oromaskevic23-cmd/main/assets/alexander-romaskevich-portrait-20261110.jpg" alt="Alexander Romaskevich" width="160"/></p>

**Alexander Nikolaevich Romaskevich (RomaskevicH)** — Founder • Owner • CEO, IMPERIAL Core. Architect / Final Architectural Decision Authority.

Public source visibility is not a license grant. See [LICENSE](LICENSE).

**Architecture Before Implementation. Evidence Before Trust.**

## Security hardening v0.2

[Implementation](src/merkle.mjs) · [Tests](test/merkle.test.mjs) · [Evidence and limitations](docs/HARDENING_V0_2.md).

## Security composition v0.3

Signed Merkle checkpoints bind organization, ledger identity, size and root; verification checks all of these against trusted context. Inclusion is not a consistency proof, external witness, timestamp or proof against signer equivocation.

[Implementation](src/signed-merkle.mjs) · [Tests](test/signed-merkle.test.mjs) · [Scope and evidence](docs/COMPOSITION_V0_3.md).
