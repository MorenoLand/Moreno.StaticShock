# Pseudocode

`python pipeline/split_pseudo.py` splits the Hex-Rays chunks in `ida/` into one file per function,
named `<address>_<name>.c`, plus `index.tsv`. These files are analysis material for reading next to
`asm/` and `src/`; they are never compiled.
