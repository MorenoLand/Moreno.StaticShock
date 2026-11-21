# Generated source

`pipeline/gen.py` writes the lifted C here, one file per class or 4 KB page, plus `protos.h`,
`dispatch.c`, `stubs.c`, `unsupported.txt` and `image.bin`.

Do not edit generated files by hand unless you also record the change in the lifter or in
`runtime/override.c`; a later `gen.py --regenerate` overwrites them.

The folder is empty until a target is configured and lifted.
