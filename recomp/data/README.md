# Generator data

Intermediate tables used by the pipeline:

- `functions.tsv` - the classified function list consumed by `gen.py`
- `api_table.json` - imports, calling convention and argument counts
- `gl_table.json` - optional OpenGL entry table
- `api_gen.c` - generated C import table (ignored, rebuilt by `gen_api.py`)

These are project data, not original assets. Keep them out of public repositories if they contain
names or strings you do not have the right to publish.
