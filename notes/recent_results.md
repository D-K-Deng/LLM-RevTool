# Recent Results

## rop_pivot

- Date: 2026-03-13 UTC
- Command:

```powershell
wsl bash -lc "cd '/mnt/e/Edu/Dartmouth/Winter 2026/COSC 269 Basics of Rev Engineering/HW/Final' && python3 -m pwngpt_pipeline.cli --unsafe-model-commands --max-iterations 1 --max-inner-rounds 15 solve --binary challenges/bin/rop_pivot --success-regex 'ROPE\\{[^}]+\\}'"
```

- Run dir: `artifacts/rop_pivot_2026-03-13T00-18-47+00-00`
- Result: `solved=true`
- Success attempt: `1`
- Success round: `4`
- Elapsed seconds: `515.786`

Round log:

1. Round 1: rejected, syntax error (`'[' was never closed at line 17`)
2. Round 2: rejected, syntax error (`invalid syntax at line 28`)
3. Round 3: verification timeout after format repair
4. Round 4: success, matched success regex in process output

## rop_fluff

- Date: 2026-03-13 UTC
- Command:

```powershell
wsl bash -lc "cd '/mnt/e/Edu/Dartmouth/Winter 2026/COSC 269 Basics of Rev Engineering/HW/Final' && python3 -m pwngpt_pipeline.cli --unsafe-model-commands --max-iterations 1 --max-inner-rounds 15 solve --binary challenges/bin/rop_fluff --success-regex 'ROPE\\{[^}]+\\}'"
```

- Run dir: `artifacts/rop_fluff_2026-03-13T21-00-26+00-00`
- Result: `solved=true`
- Success attempt: `1`
- Success round: `2`
- Elapsed seconds: `1306.508`

Round log:

1. Round 1: first draft rejected for missing constrained write primitive; second draft reached verifier but exited without success markers
2. Round 2: several non-counted drafts were rejected for incomplete constrained-write logic; draft 9 succeeded and matched success regex

## rop_all_eval

- Date: 2026-03-13 UTC
- Command:

```powershell
wsl bash -lc "cd '/mnt/e/Edu/Dartmouth/Winter 2026/COSC 269 Basics of Rev Engineering/HW/Final' && python3 -m pwngpt_pipeline.cli --unsafe-model-commands --max-iterations 1 --max-inner-rounds 15 eval --manifest challenges/manifest_rop_all.json"
```

- Eval dir: `artifacts/eval_2026-03-13T21-46-09+00-00`
- Result: `solved=8/8`
- Success rate: `1.000`

Rows:

1. `rop_ret2win`: solved, run `artifacts/rop_ret2win_2026-03-13T21-46-09+00-00`
2. `rop_split`: solved, run `artifacts/rop_split_2026-03-13T21-46-15+00-00`
3. `rop_callme`: solved, run `artifacts/rop_callme_2026-03-13T21-46-21+00-00`
4. `rop_write4`: solved, run `artifacts/rop_write4_2026-03-13T21-46-27+00-00`
5. `rop_badchars`: solved, run `artifacts/rop_badchars_2026-03-13T21-46-32+00-00`
6. `rop_fluff`: solved, run `artifacts/rop_fluff_2026-03-13T21-46-38+00-00`
7. `rop_pivot`: solved, run `artifacts/rop_pivot_2026-03-13T21-53-45+00-00`
8. `rop_ret2csu`: solved, run `artifacts/rop_ret2csu_2026-03-13T23-31-57+00-00`
