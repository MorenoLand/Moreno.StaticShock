# IDA export

`pipeline/ida_export.py` writes the analysis export here:

- `functions.tsv` - address, name, size, library flag
- `segments.txt` - sections and entry point
- `imports.txt` - module, IAT address, name, ordinal
- `strings.tsv` - address and text
- `chunk_*.c` - Hex-Rays pseudocode, for reading only
- `index.tsv` - pseudocode index

The `.i64` database is ignored. Do not commit original binaries or IDA databases.
