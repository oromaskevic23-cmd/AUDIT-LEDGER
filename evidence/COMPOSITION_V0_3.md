# Security composition v0.3 — local acceptance evidence

Node.js v22.16.0. Exact v0.1 and v0.2 source blobs matched the preceding GitHub revisions. New module and test blobs matched all four GitHub candidate commits.

- ZERO-TRUST: 0196f6632cae43b34d7891d821683a27f68029b9
- GUARDIAN-CORE: 9a4ddeb1f78de5eeef10c96966349bd28388610b
- APPROVAL-GATEWAY: b61099decc617fde18e1ee4908340297c03b3d12
- AUDIT-LEDGER: 1059d16e69b1a73f57ae1b659c4bd4c84205d67d

Place sibling checkouts at those revisions and execute from their parent directory: `node --test */test/*.test.mjs AUDIT-LEDGER/integration/*.test.mjs`.

Result: 75/75 PASS, 0 failures; 17 new unit tests, 6 new integration tests. Integration blob: e3ce41eec3f3bc045ba17fbfae77251b3ac8157e.

Synthetic test keys exercise identity admission, revoked subject, signed policy tampering, global veto, policy epoch mismatch, persistent replay denial after database reopen, and signed Merkle inclusion for the synthetic event.

Limitations: host configuration and state are trusted inputs; no production issuer, durable authoritative epoch distribution, resource-side enforcement, atomic execution/audit, external witness, independent QA or real Owner Face ID enrollment. The legacy APIs are retained and can bypass the new composition if misused; production hosts must require the composed path. SQLite is experimental in tested Node version. No real task was executed, and no cloud or paid resources were used.
