## What changed

<!-- One paragraph. Name the stage: analysis, lift, runtime, imports, host, build, evidence. -->

## Why

<!-- The bug or missing behaviour, with the first incorrect value if this is a fix. -->

## Evidence

<!-- Differential test, trace, dumped buffer, screenshot, doctor/readiness output. -->

## Checks

- [ ] `python static_shock.py verify` passes
- [ ] `python static_shock.py readiness` did not regress
- [ ] a test or a reproducible comparison covers the change
- [ ] no original executable, asset, key or proprietary code is included
- [ ] no stubs, inline assembly, fake patches or invented behaviour
- [ ] generated C stays instruction-faithful; readable rewrites are separate
- [ ] docs and records are updated if behaviour changed

## Notes

<!-- Anything the reviewer should know, including limitations. -->
