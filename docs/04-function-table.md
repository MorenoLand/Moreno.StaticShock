# Function table and classification

## make_functions.py

Converts the IDA table into the form the lifter consumes:

```sh
python pipeline/make_functions.py
```

Output: `recomp/data/functions.tsv` with `ea`, `name`, `size`, `category`. Library functions
(`lib=1`) become `lib:crt`; everything else `app`.

## classify.py

Optional but recommended. It refines categories and can split the image into ranges (CRT, known
libraries, application). Configure `[[classify.ranges]]` in `project.toml`:

```toml
[classify]
ranges = [[0x401000, 0x500000, "app"], [0x500000, 0x600000, "lib:crt"]]
```

Unlisted addresses become `other`. `gen.py` skips categories listed in `lift.skip_categories`
(default `other`).

## Why classification matters

- `group_of()` uses the category to name source files. A `lib:crt` function goes to `crt/`; a
  known class goes to its class file.
- Third-party libraries can be replaced by native libraries later; keeping them separate makes
  that swap mechanical.
- Skipping `other` avoids lifting data that IDA mistook for functions.

## Sanity checks

- The sum of function sizes should be plausible for the executable section.
- Spot-check 10 addresses: the bytes at `ea` should look like a function prologue, and the next
  function should start at `ea + size` or after alignment.
- `functions.tsv` should not contain addresses outside `code_lo..code_hi` unless they are imports
  or thunks.
