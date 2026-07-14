## AI GENERATED AI GENERATED AI GENERATED AI GENERATED AI GENERATED AI GENERATED AI GENERATED AI GENERATED

# devirtualize.py — full deobfuscator for jactorv4 (LuaU/5.1)

Turns a VM-obfuscated Luau/Lua script into **runnable Lua source**, in the three
stages you asked for:

```
obfuscated .lua  ->  devirtualize (recover Lua 5.1 opcodes)
                 ->  pseudo listing  (<out>.pseudo.txt, human-readable)
                 ->  Lua 5.1 bytecode (<out>.luac)
                 ->  unluac           ->  runnable Lua (<out>)
```

## Usage

```
python devirtualize.py <input.lua> [output.lua]
```
or on Windows:
```
devirtualize.bat <input.lua> [output.lua]
```

Requirements: **Python 3**, **Java**, and **unluac.jar** (already in this repo).

Outputs written next to `[output.lua]`:
- `<out>.pseudo.txt` — the devirtualized opcode listing (one line per instruction,
  with the raw operand slots). This is the "pseudo lua" intermediate.
- `<out>.luac` — reconstructed Lua 5.1 bytecode (this obfuscator is a 1:1
  virtualization of Lua 5.1 bytecode).
- `<out>` — the final runnable Lua source, produced by unluac.

## What it handles

Everything is re-derived from each sample's own interpreter, so per-sample
shuffling is automatic:

- **string decoders** (base-93 / LZW + hex-pair) for the constant blob and the
  instruction/constant tables;
- **prototype layout** — which numeric slot holds code / constmap / subprotos /
  numparams / nups (these are fully permuted per sample, e.g. code may be slot 1
  in one sample and slot 2 in another);
- **split delimiters**, in both the method form `x:split("A")` and the
  function form `split(x,"A")`;
- **VM variable roles** (register file, instruction, globals, upvalues, loop-top,
  varargs, call/close helpers) identified structurally, not by name;
- **opcode map** — all 37 Lua 5.1 operations, recognised by the *shape* of each
  handler body so opcode-number shuffling doesn't matter. Both VM variants are
  supported:
  - the **specialized** variant (constant-vs-register baked into distinct
    opcodes → ~75 handlers), used by the newer samples;
  - the **runtime-RK** variant (constant-vs-register chosen from a flag field →
    ~38 handlers), used by the older `sample29`.
- **CLOSURE upvalue captures** — the pseudo-instruction rows that follow a
  CLOSURE are consumed and re-emitted as `MOVE` / `GETUPVAL`.

If a handler shape is ever unrecognised it is reported loudly
(`WARN unknown handler ...`) instead of being silently guessed.

## Notes / limitations

- The reconstructed bytecode is byte-accurate; strings/numbers come straight
  from the sample's constant blob.
- Scripts that used Luau `continue` or `A and B or C` short-circuits decompile
  to `goto`/labels (valid Lua 5.2+). That is an unluac output characteristic,
  not an error in the devirtualization — the logic is faithful. Small scripts
  with no such constructs (e.g. `obfuscated (2)`) come out as clean Lua 5.1.
- The older Lua-based scripts in this repo (`deobfuscate_full.lua` etc.) only
  handle the runtime-RK variant; `devirtualize.py` supersedes them for the
  newer specialized variant and handles both.
