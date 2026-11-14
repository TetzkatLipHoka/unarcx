# Unpacking ElAmigos / ISDone Inno installers (workflow)

Short guide to **unpack a password-protected Inno Setup repack (ISDone.dll +
FreeArc/unarc + lolz/srep codecs) offline, without running the installer**.
Tested on *Shin Megami Tensei III Nocturne HD — ElAmigos*.

> Scene binaries (unarc.dll, cls-*.dll, *.exe workers) are untrusted. On the
> first run, do it in a throwaway VM with a snapshot and no network.
> Static triage of this toolchain (13 binaries, 2026-11-14): no network
> imports/strings, no registry writes/service/injection; `CreateProcess` =
> codec workers. Clean within the limits of static analysis.

## 1. Get the installer password (if the installer itself is encrypted)

```
innounp.exe -crack setup.exe
```
Recovers the Inno password from the compiled PascalScript. Alternatively
`innounp.exe -showpass setup.exe` for the hash/salt (offline cracking).

## 2. Get the ARC password(s) from the compiled code

The ARC passwords sit as **plaintext literals** in the compiled code, right at
the `ISArcExtract` call. Dump CompiledCode …

```
innounp.exe -x -m -b -p"<installer-pw>" setup.exe "embedded\CompiledCode.bin"
```

… then find the passwords — fastest via strings, or inspect the `ISArcExtract`
call sites in the IFPS disassembly:

```
strings embedded\CompiledCode.bin          # high-entropy PW strings
# or search the disassembly for "ISArcExtract" / loc_*
```

**Note:** there can be **multiple** passwords for **multiple archive sets**
(separate `ISArcExtract` paths, sometimes inside `FindFirst/FindNext` loops).
Example SMT3HD:
- `elamigos-1.bin`  →  `5yyux2X*jzZWiW3H49eQ9t*c2MK79`
- further parts     →  `6Hsdr96#vTewJ4ebmrf7XxkLsbHcJ`

## 3. Extract the bundled codec toolchain

```
innounp.exe -x -b -p"<installer-pw>" -dtool setup.exe "{tmp}\*"
```
Yields, among others, `unarc.dll`, `arc.ini`, `cls.ini`, `cls-lolz*.{dll,exe}`,
`cls-bpk.dll`, `CLS-srep.dll`, `srep64.exe`, `facompress*.dll`. **Use these
original files** — stock FreeArc / freearc-c do not know the `lolz` codec.

## 4. Extract with unarcx

Put `unarcx.exe` + the archives (`elamigos-*.bin`) into the toolchain folder
(`tool\{tmp}\`) and start it **from that folder** — the codec plugins are loaded
by name from the CWD. Run it **as Administrator** (the lolz/srep workers use
`Global\` shared memory → needs elevation, otherwise "Can't create/open ...
mapping!").

```
unarcx.exe <archive> <outdir> <arc-password> [mask ...]
```
Only the dump-relevant files:
```
unarcx.exe elamigos-1.bin out "5yyux2X*jzZWiW3H49eQ9t*c2MK79" "*global-metadata.dat" "*GameAssembly.dll" "*il2cpp*"
```

### Tuning, if needed
- **Immediate `-1` / general error:** drop the `-cfg` argument (the
  `AddArg('-cfg'…)` line in the source) — `arc.ini` is usually auto-loaded from
  the CWD.
- **Crash on the first callback:** in the source switch `ArcCallback` from
  `stdcall` to `cdecl` (calling convention; the default is `stdcall` per
  `unarcdll.h`).
- **External workers can't find temp:** add `AddArg('-w' + workdir)`.

## How unarcx works (RE note)

`unarc.dll` export ord. 2 = `FreeArcExtract(callback, cmd1, …, NULL)` (`__cdecl`,
args like the unarc CLI, list ends at NULL/empty string). Passing a callback
sets the internal "encryption enabled" flag. When needed the DLL fires the event
`what="password?"` (`int1`=buffer size, `str`=password buffer); the callback
copies the password into `str` and returns **121 (`'y'`)**. Crypto:
PBKDF2 (pkcs5) + AES-256/CTR, checked against the `:c` value in the method
string. No ISDone, no window handles required.
