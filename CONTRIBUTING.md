# Contributing to StaticShock

Thanks for being here. This project exists so people can preserve software they own, understand
how it works, and keep it running. Contributions that move correctness forward are welcome.

## The one rule

Use it only on software you legally own and are allowed to reverse engineer. Do not commit an
original executable, game assets, extracted proprietary content or keys. A pull request that adds
any of those will be closed. See [LEGAL.md](LEGAL.md).

## Ways to help

- Port the template to another target and report what broke.
- Add a lifter case, an import bridge, or a runtime fix.
- Add a differential test, a replay, or a source-built fixture.
- Improve the docs with a reproducible workflow.
- Triage an issue with a minimal reproduction.

## Setup

```sh
python -m pip install -r requirements.txt
python static_shock.py doctor
```

You need a 32-bit MinGW-w64 (`i686-w64-mingw32-gcc`) and, for the default backend, IDA with
Hex-Rays. An external native analyzer can be used instead; see
[docs/20-analysis-backends.md](docs/20-analysis-backends.md).

## Before you code

- Read [AGENTS.md](AGENTS.md) and [docs/05-lifting.md](docs/05-lifting.md).
- Find the first incorrect value, not the last visible symptom.
- Write down the claim and its evidence (`docs/17-evidence.md`). "It builds" is not evidence.
- Keep generated code instruction-faithful. Readable rewrites are separate and must be verified.

## Pipeline

```sh
python static_shock.py analyze --provider ghidra   # or: python static_shock.py ida
python static_shock.py functions
python static_shock.py lift
python static_shock.py api
python static_shock.py manifest
python static_shock.py inventory
python static_shock.py build
python static_shock.py verify
python static_shock.py readiness
```

## What a good change looks like

- It fixes one clear problem and does not lower correctness elsewhere.
- It includes evidence: a differential test, a trace, a dumped buffer, or a reproducible comparison.
- It does not add a stub, a no-op, inline assembly, a fake patch or invented behaviour.
- It keeps the generated C separate from hand-written overrides.
- It updates the docs and the evidence/inventory records when the behaviour changes.
- It does not change unrelated files.

## Tests

- `python static_shock.py verify` must pass.
- `python static_shock.py readiness` should not regress.
- Add a differential case for a lifter or runtime change.
- Add a replay or a screenshot comparison for host behaviour.
- `python tests/run_wasm_test.py` when the wasm host or `runtime/rt.c` changes.
- Never commit the original binary the test needs; gate it on `SS_EXE` and skip when absent.

## Commits and pull requests

- Use a short message that describes the actual change. `fix`, `update` or `push` is not a message.
- Keep commits focused. Do not mix a lift change with a formatting sweep.
- Sign commits if you have a signing key; the maintainer's repository requires signed commits.
- Open a pull request with the template. Explain the target, the symptom, the evidence and the
  commands you ran.
- Do not add co-author trailers or generated-by lines.

## Bugs and security

- Functional bugs: open an issue with the bug form, including `doctor` output and a minimal
  reproduction.
- Security issues: do not open a public issue. Follow [SECURITY.md](SECURITY.md).

## Community

Be decent. Read [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Technical disagreement is fine; personal
attacks, harassment and piracy are not.

## License

By contributing you agree that your contribution is licensed under the MIT license in
[LICENSE](LICENSE). Keep the copyright and permission notice with copies of the project.
