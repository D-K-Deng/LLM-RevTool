# Toy Challenges

## Build

```bash
cd challenges
bash build.sh
```

## Included binaries

- `branch_puzzle`: input check, prints `WIN`.
- `stack_overflow`: overwrite RIP to call `win()`.
- `format_string`: format string write to set global `auth`.
- `integer_edge`: signed/unsigned wraparound path.

These binaries are intentionally simple and local-only for iterative pipeline testing.
