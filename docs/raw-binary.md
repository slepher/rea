# Headerless raw-binary analysis with Ghidra

REA admits a headerless executable when the caller supplies the CPU family and
the address where file offset 0 should be mapped. That interpretation is not
inferred from a `.bin` suffix or from unrecognized bytes.

## Open and inspect

```bash
rea inspect /absolute/path/to/ecu.bin --target-format raw-binary --architecture arm --entry-point 0x8000000 --provider ghidra --json
rea function /absolute/path/to/ecu.bin 0x8000000 --target-format raw-binary --architecture arm --entry-point 0x8000000 --provider ghidra --json
rea inspect-native-load-image /absolute/path/to/ecu.bin --target-format raw-binary --architecture arm --entry-point 0x8000000 --provider ghidra --json
```

```json
{
  "name": "open_binary",
  "arguments": {
    "path": "/absolute/path/to/ecu.bin",
    "format": "raw-binary",
    "architecture": "arm",
    "entry_point": "0x8000000",
    "provider_id": "ghidra"
  }
}
```

`architecture` is one of `x86`, `x86_64`, `arm`, `arm64`, `6502`, or `riscv`. `entry_point` is a
hexadecimal address of the form `0x…`. The complete file is mapped starting at
`base_address` (defaults to `entry_point`), and Ghidra seeds an `entry` function
at `entry_point` before auto-analysis. The entry must be within the mapped file.
ARM and AArch64 entries must be 4-byte aligned; x86 and 6502 entries may be byte-aligned.
For 6502, the entry and complete mapped file must fit within `0x0000..0xffff`;
images that cross the 16-bit boundary are rejected before provider startup.
`open_binary` and an open `binary_session` return the canonical `entry_point`
for raw targets so callers can verify the selected mapping directly.
Omitted `format` keeps header-based detection; architecture and entry without
`format=raw-binary` are rejected.

Ghidra imports a private snapshot with `BinaryLoader` and these little-endian
generic languages and compiler specifications:

| architecture | language_id          | compiler_spec_id |
| ------------ | -------------------- | ---------------- |
| x86          | `x86:LE:32:default`  | `gcc`            |
| x86_64       | `x86:LE:64:default`  | `gcc`            |
| arm          | `ARM:LE:32:v7`       | `default`        |
| arm64        | `AARCH64:LE:64:v8A`  | `default`        |
| 6502         | `6502:LE:16:default` | `default`        |

Compiler specifications select analysis conventions; they do not identify the
original compiler or ABI of a headerless target. Ghidra's x86 languages do not
provide a compiler specification named `default`.

Those settings, the caller-supplied entry, and `language_selection:
caller-supplied-v1` are committed in the analysis profile. A different entry
or architecture, RISC-V bit width, or mapping base is a different profile; snapshots from header-detected targets
do not replay.

The mapped start is independent of Ghidra's program image base, which remains
`0x0` for BinaryLoader. Ghidra may report additional language-defined entry
points, including unmapped ARM vectors. Load-image verification requires the
caller-supplied entry and preserves those other entries as observations.
For 6502, BinaryLoader maps the file before adding its language-defined zero-page
and stack blocks. Conflicting default blocks are skipped; low-address files stay
in the default address space rather than an overlay. Non-conflicting uninitialized
blocks remain observations, not file-backed bytes.
Independent raw verification streams the complete private snapshot digest and
extent with bounded memory and supports cancellation during the read.
It also requires the source-backed block to be initialized, loaded, and
non-overlay in the bound language's default address space. Contradictory mapping
observations are retained with `mismatch`, even when the source hashes agree.

Hopper and IDA refuse raw-binary targets. Windows Ghidra P0 admits native PE
applications/DLLs and explicitly selected raw 6502 or RV32/RV64 RISC-V images. Other raw CPU families
remain outside the Windows boundary. Native path admission, private DACLs, Job
Object ownership, immutable snapshots, and the no-mutation policy still apply.

## NMOS 6502

```bash
rea function /absolute/path/to/image.bin 0x8001 --target-format raw-binary --architecture 6502 --entry-point 0x8001 --provider ghidra --json
rea inspect-native-load-image /absolute/path/to/image.bin --target-format raw-binary --architecture 6502 --entry-point 0x8001 --provider ghidra --json
```

Select only headerless NMOS 6502 code with a known entry at file offset 0.
The built-in Ghidra processor supplies static instructions, functions,
pseudocode, and references. Evidence preserves `architecture: "6502"`, the
selected language, entry, file digest, and verified source mapping. Register and
calling conventions are analysis conventions, not a recovered source ABI.

This lane does not interpret iNES headers, cartridge mappers, bank switching,
or other console-specific memory layouts. 65C02 and 65816 programs need different
processor semantics and are not admitted as those variants. REA does not infer
the CPU from the file suffix, guess the reset vector, or emulate the target.

`npm run verify:ghidra:6502` assembles and links the source-owned fixture with
`ca65` and `ld65` (tested from cc65 tag `V2.19`, whose tools report `V2.18`).
Set `REA_CA65` and `REA_LD65` to explicit executable paths if needed. The lane
checks real CLI/MCP load-image parity, mapped bytes, decoded calls, decompilation,
invalid mappings, unchanged source bytes and runtime cleanup.
Low-memory checks include a file spanning the zero-page/stack boundary at `0xff`
and a complete 64-KiB image at `0x0`, with verified default-space mappings through
both CLI and MCP. On Windows, the lane also checks that a caller-selected
junction path is rejected at snapshot admission through CLI and MCP, with
unchanged source bytes and complete runtime cleanup. Windows requires the
matching native addon; the POSIX provider path has not been exercised by the
Windows run.

## Limitations

- Headers are not discovered from file bytes. This increment does not guess
  load addresses, vector tables, or memory maps.
- Big-endian, Thumb-only, Cortex-M, and other Ghidra processor variants are
  unsupported.
- Reset vectors, memory-mapped I/O, and firmware boot sequences are not
  emulated.
- Independent load-image verification covers source identity, mapped file
  bytes, the bound language, and the caller-supplied entry. Original bytes
  stay unchanged.

## RISC-V raw images

Select `architecture=riscv` and explicitly supply `bit_width=32` or `64`.
REA pins `RISCV:LE:32:default` or `RISCV:LE:64:default` with compiler spec `gcc`.
Width is never guessed from addresses or bytes. Other architectures reject
`bit_width`. Entries must be 2-byte aligned (compressed instructions are allowed),
and the complete mapping must fit the selected address width.

```bash
rea inspect-native-load-image /absolute/path/firmware.bin --target-format raw-binary --architecture riscv --bit-width 32 --base-address 0x9ffff000 --entry-point 0xa0000000 --provider ghidra --json
```

The corresponding `open_binary` MCP arguments are `format: "raw-binary"`,
`architecture: "riscv"`, `bit_width: 32`, `base_address: "0x9ffff000"`, and
`entry_point: "0xa0000000"`, together with the absolute `path`. File offset zero
maps at the base; offset `0x1000` is the code entry. Both values participate in
profile/snapshot identity. Equivalent hexadecimal spellings retain reuse.
Omitting the base preserves the existing base-equals-entry behavior.

The original ABI is unknown. The generic `gcc` compiler convention does not
establish floating-point parameter recovery, vendor/custom instruction semantics,
or boot behavior. ELF admission and its ABI requirements remain unchanged.
Windows x64 supports this raw lane with the matching package-owned native addon,
private NTFS runtime, and Job Object ownership. Database mutation remains unavailable.
RISC-V ELF admission on Windows remains unsupported.

After `npm run build:cached`, run `node scripts/verify-real-ghidra-riscv-raw.mjs`
with BYO `GHIDRA_INSTALL_DIR` and a full JDK21+ via `JAVA_HOME`. It generates
source-owned standard RV32/RV64 instructions (no target execution), checks real
CLI/MCP mapping, calls, global references, pseudocode, canonical reuse, source
immutability and owned cleanup. The source is
`tests/conformance/ghidra/riscv-raw-fixture.mjs`; no private firmware is required.
