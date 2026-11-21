# RTTI inventory

RTTI is one of the few places where a stripped MSVC binary still states its own class names. The
tooling treats every recovered link as evidence and refuses to guess the rest.

## Run it

```sh
python static_shock.py rtti
```

Outputs:

- `recomp/data/rtti_names.tsv` - `ea`, `name`, `kind` (`class`, `vftable`, `vfunc`)
- `recomp/data/rtti.json` - classes, vtables, base classes, methods and counts

The inventory picks it up automatically: a function that appears in a vtable gets an
`rtti_names` list and an `rtti` evidence entry.

## What is validated

For a 32-bit MSVC image:

1. **Type descriptor** - a `.?AV<name>@@` or `.?AU<name>@@` string. The descriptor starts 8 bytes
   before the name (type_info vftable + spare). Its vftable pointer must point into the image.
2. **Complete object locator** - a reference to the descriptor, 12 bytes into a locator with
   signature `0`, the descriptor pointer at `+12` and a class-hierarchy pointer at `+16`.
3. **Vtable** - a reference to the locator. The vtable starts at the next dword (`vtable[-1]` holds
   the locator). Slots are read while they point into `.text`.
4. **Class hierarchy** - the class-hierarchy descriptor's base array, each base pointing to another
   validated type descriptor. The first base is the class itself and is omitted.

A descriptor with no valid locator is counted as an orphan. It is not turned into a vtable or a
method list.

## What the names mean

- `rtti_Class` - the type descriptor address.
- `vftable_Class` - the vtable address.
- `Class::vfuncN` - the Nth slot in that vtable, pointing at a code address.

`vfuncN` is positional. It is evidence that the function occupies slot N of that class's vtable.
It is not proof of the method's semantic name. Use the slot order, base classes, strings and call
sites together before adopting a readable name.

## Accuracy rules

- Do not rename a function from RTTI alone unless the slot is unambiguous. Record the class, slot
  and vtable in the evidence.
- A function can appear in several vtables (inheritance, thunks, secondary vtables). Keep all the
  names; do not pick one silently.
- An orphan descriptor is not a class with no methods; it is a descriptor whose locator was not
  validated. Say so.
- The tool does not decode Itanium/GCC RTTI, 64-bit RTTI, or PDB/CodeView symbols. Those are
  separate backends.
- Vtable slot order is provider-independent only for the same binary and compiler settings. Do not
  compare slots across builds.

## Integrating with the inventory

`inventory.json` adds:

```json
{
  "address": "0x00401280",
  "rtti_names": ["BaccaratAI::vfunc0"],
  "evidence": ["function table", "rtti"]
}
```

`name_confidence` stays `none` for an address-derived name. The RTTI name is extra evidence, not a
license to claim the function's purpose.

`rtti.json` also records the class base list, which is useful for grouping functions even when the
method names are not known.
