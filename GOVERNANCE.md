# Governance

StaticShock is maintainer-led and contribution-friendly.

## Principles

- Correctness over speed.
- Evidence over opinion.
- Small, reviewable changes.
- No invented behaviour, no fake fixes.
- Only software people legally own.

## Roles

- **Maintainer** - reviews and merges changes, owns releases and the evidence records, handles
  security and conduct reports.
- **Contributors** - submit issues, tests, ports, fixes and documentation.
- **Users** - build their own projects from the template and report what breaks.

## Decisions

Routine fixes use lazy consensus: a pull request with evidence and no unresolved objection is
merged. Changes to the pipeline model, the runtime ABI, the license or the governance are announced
in an issue first and need the maintainer's approval.

When there is no consensus, the maintainer decides and records the reason. A decision can be
revisited with new evidence.

## Releases

- `master` is the supported branch.
- A release is a tagged commit whose `verify` and `readiness` records are current.
- Release notes describe real changes, not every commit.
- Broken builds, failing required checks or pending fixes do not get a release.

## Scope

The project is a template and toolkit. It does not ship original executables, game assets or keys.
Target-specific work belongs in the user's copy, not in the template.

## Conduct and security

See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) and [SECURITY.md](SECURITY.md). Reports are handled
privately.
