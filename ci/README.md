# Reproducible PR library checks

PR CI builds actual sibling sources at the versions already represented by the protocol lockfile: decentralized-minting 3.0.1 at `bfe3542bf262363faa7c8a11740a254f46e1e347` and kora-secrets-crypto 1.0.0 at `f1d9dc9f88c7fd9d63aa5a5afabaea6fbbde1080`. They occupy the sibling paths required by the existing `file:../...` dependencies. No package manifest/version, runtime code, contracts, validators, or generated library is changed or substituted.

`prepare-library-builds.mjs` rejects mismatched package versions, checks the original common 5.1.41 integrity and distribution URL, then changes only its stale distribution URL in the ephemeral SDK lock. The alternate GitHub archive was downloaded and SHA512-verified against that existing integrity before introducing the mapping. Dependency versions, integrity, metadata and all other lock entries stay intact. Only the built-in Actions token with packages:read is used; no operator secret is copied into CI. Unexpected or missing inputs fail rather than falling back.

The workflow runs frozen sibling installs, both real TypeScript library builds, then the protocol's locked install, typecheck, and build. Tests are local-only: run the helper and publication-policy regression tests and the complete existing behavioral suite locally, never in Actions, including through package lifecycle scripts, composites, templates, or shared helpers. It does not run a validator compiler, submit transactions, deploy or publish anything. Build success alone is not behavioral acceptance.

## Publication policy

The existing publication workflow ignores only the six exact CI paths listed in its push filter. Source, package-manifest and lockfile pushes, including mixed source/CI commits, still select that workflow; workflow_dispatch remains available. `publish-policy.test.mjs` parses the actual YAML using the SDK's already locked YAML dependency and evaluates this narrow event/path contract. Its negative controls remove the exclusion, replace it with a blanket ignore, and remove manual dispatch: each must violate the policy assertions. These are configuration-policy tests, not a live npm publication test. No source push or publication is performed to test these guards.

## Helper test invariants and controls

- URL correction preserves the original object and every output field except the archive URL; removing the replacement or changing any other locked field fails the output assertions.
- Already-corrected inputs are idempotent; rejecting or rewriting a valid corrected lock fails the equality assertion.
- Different versions, checksums and distribution hosts are rejected without mutation; removing the corresponding guard fails the rejection assertion.
- Missing archives are not invented; accepting a missing entry fails the rejection assertion.
- Only the exact sibling source versions are accepted; accepting 4.0.0 instead of the locked 3.0.1 fails the rejection assertion.

Any failure of the historical sibling build or existing local protocol suite remains a real gap. CI does not import unpublished checkout changes or rewrite runtime expectations to force success.
