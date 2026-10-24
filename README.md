# Servar

A CLI tool that uses systematic BCH codes to protect files against bitrot. It can generate a checksum/parity file, verify integrity via SHA-256, and recover damaged files.

## Features

- Computes SHA-256 of the source file and stores it in the checksum file.
- BCH-encodes `file data + SHA-256` in blocks, so both data and hash are protected.
- Verification recomputes SHA-256: if it matches, the file is intact; otherwise BCH-based recovery is attempted.
- Multi-threaded encode/repair for large files.
- Memory-mapped I/O and fast SHA-256 via OpenSSL.
- Configurable error correction ratio, down to 1/16000
- By default, ~1% of the file size is used to repair up to 0.1% of random flips.
- Not suitable for burst errors, such as bad sectors. Please use RS-code-based recovery files instead, such as par2.

## Requirements

- **Zig 0.18.0-dev** (tested with `0.18.0-dev.367+187d0bf9e`). The source uses the new `std.Io` / `std.process.Init` APIs, so older Zig releases may not compile.
- **OpenSSL development files** (`libcrypto`). SHA-256 is linked from OpenSSL because it is substantially faster than the scalar Zig standard-library implementation on CPUs without SHA-NI.


## Build

```bash
# Development build (Debug; slower, useful for debugging)
zig build

# Recommended release build (ReleaseFast)
zig build -Drelease=true

# Equivalent explicit form
zig build --release=fast

# Install to a custom prefix (binary goes to <prefix>/bin/servar)
zig build -Drelease=true --prefix /usr/local

# Run the unit tests
zig build test

# Run the unit tests in release mode
zig build test -Drelease=true
```

The default output is `zig-out/bin/servar`.

## Usage

```bash
servar encode <input> [-o output] [--m M] [--t T] [--no-hash]
servar verify <input> [checksum]
servar repair <input> [checksum]
servar help
```

- Default checksum file: `<input>.ser`
- Default parameters: `m=13`, `t=8` (K≈1010 bytes per block).
- `--no-hash`: disable SHA-256 storage/verification and skip hashing during
  encode (BCH-only mode). The checksum still contains a zeroed 32-byte hash
  field so the file format remains compatible.
- Checksum (`.ser`) size: roughly 1.3% of the source file for default
  parameters (`m=13`, `t=8`), plus a small fixed header.

## Examples

```bash
servar encode data.bin
servar verify data.bin
servar repair data.bin

# BCH-only checksum (no SHA-256 pass)
servar encode data.bin --no-hash
servar verify data.bin
servar repair data.bin
```

## Performance

Measured on an Intel(R) Core(TM) i5-8350U CPU @ 1.70GHz (8 threads), Linux,
OpenSSL 3.0.15, ReleaseFast, with the test file stored in tmpfs. Values are
medians of 5 runs; the CPU governor was `powersave`, so absolute numbers vary
with frequency scaling and system load.

| File size | `.ser` size | Encode | Verify | Repair (1000 bit flips) |
|-----------|-------------|--------|--------|-------------------------|
| 1 GiB     | 13.2 MiB    | 4.0 s  | 3.1 s  | 5.3 s                   |


## Checksum format

Binary `.ser` file:

- Magic: `SERVAR` (6 bytes)
- Version: u16
- BCH parameters (m, t, K, ecc_bytes)
- Original file size, number of blocks
- SHA-256 hash (32 bytes; all zero when encoded with `--no-hash`)
- Original basename
- Parity bytes for every block
