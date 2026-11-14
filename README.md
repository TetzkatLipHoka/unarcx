# Entpacken von ElAmigos / ISDone-Inno-Installern (Workflow)

Kurzanleitung, um einen passwortgeschützten Inno-Setup-Repack (ISDone.dll +
FreeArc/unarc + lolz/srep-Codecs) **offline zu entpacken, ohne den Installer
auszuführen**. Getestet an *Shin Megami Tensei III Nocturne HD — ElAmigos*.

> Scene-Binaries (unarc.dll, cls-*.dll, *.exe-Worker) sind untrusted. Beim
> ersten Mal in einer Wegwerf-VM mit Snapshot und ohne Netz laufen lassen.
> Statische Triage dieser Toolchain (13 Binaries, 2026-11-14): keine Netzwerk-
> Imports/-Strings, kein Registry-Write/Service/Injection; `CreateProcess` =
> Codec-Worker. Sauber im Rahmen statischer Analyse.

## 1. Installer-Passwort holen (falls der Installer selbst verschlüsselt ist)

```
innounp.exe -crack setup.exe
```
Holt das Inno-Passwort aus dem compilierten PascalScript. Alternativ
`innounp.exe -showpass setup.exe` für Hash/Salt (Offline-Cracking).

## 2. ARC-Passwort(e) aus dem CompiledCode holen

Die ARC-Passwörter stehen als **Klartext-Literale** im compilierten Code, direkt
beim `ISArcExtract`-Aufruf. CompiledCode dumpen …

```
innounp.exe -x -m -b -p"<installer-pw>" setup.exe "embedded\CompiledCode.bin"
```

… dann die Passwörter finden — am schnellsten per Strings, oder im IFPS-Disasm
die `ISArcExtract`-Callsites ansehen:

```
strings embedded\CompiledCode.bin          # hochentropische PW-Strings
# bzw. im Disasm nach "ISArcExtract" / loc_* suchen
```

**Achtung:** Es kann **mehrere** Passwörter für **mehrere Archiv-Sets** geben
(getrennte `ISArcExtract`-Pfade, teils in `FindFirst/FindNext`-Schleifen).
Beispiel SMT3HD:
- `elamigos-1.bin`  →  `5yyux2X*jzZWiW3H49eQ9t*c2MK79`
- weitere Teile     →  `6Hsdr96#vTewJ4ebmrf7XxkLsbHcJ`

## 3. Die mitgelieferte Codec-Toolchain extrahieren

```
innounp.exe -x -b -p"<installer-pw>" -dtool setup.exe "{tmp}\*"
```
Liefert u. a. `unarc.dll`, `arc.ini`, `cls.ini`, `cls-lolz*.{dll,exe}`,
`cls-bpk.dll`, `CLS-srep.dll`, `srep64.exe`, `facompress*.dll`. **Diese
Original-Dateien benutzen** — Stock-FreeArc/freearc-c kennen den `lolz`-Codec
nicht.

## 4. Entpacken mit unarcx

`unarcx.exe` + die Archive (`elamigos-*.bin`) in den Toolchain-Ordner (`tool\{tmp}\`)
legen und **aus diesem Ordner** starten — die Codec-Plugins werden per Name aus
dem CWD geladen. **Als Administrator** ausführen (die lolz/srep-Worker nutzen
`Global\`-Shared-Memory → braucht Elevation, sonst „Can't create/open mapping!").

```
unarcx.exe <archiv> <outdir> <arc-passwort> [maske ...]
```
Gezielt nur die Dump-relevanten Dateien:
```
unarcx.exe elamigos-1.bin out "5yyux2X*jzZWiW3H49eQ9t*c2MK79" "*global-metadata.dat" "*GameAssembly.dll" "*il2cpp*"
```

### Tuning, falls nötig
- **Sofort `-1` / general error:** `-cfg`-Argument weglassen (im Source die
  `AddArg('-cfg'…)`-Zeile) — `arc.ini` wird i. d. R. aus dem CWD auto-geladen.
- **Crash beim ersten Callback:** im Source `ArcCallback` von `stdcall` auf
  `cdecl` umstellen (Aufrufkonvention; Default ist `stdcall` laut `unarcdll.h`).
- **Externe Worker finden Temp nicht:** `AddArg('-w' + workdir)` ergänzen.

## Wie unarcx funktioniert (RE-Notiz)

`unarc.dll` Export ord. 2 = `FreeArcExtract(callback, cmd1, …, NULL)` (`__cdecl`,
Args wie unarc-CLI, Ende bei NULL/Leerstring). Ein übergebener Callback setzt
intern das „Verschlüsselung aktiv"-Flag. Bei Bedarf feuert die DLL das Event
`what="password?"` (`int1`=Puffergröße, `str`=Passwort-Puffer); der Callback
kopiert das Passwort in `str` und gibt **121 (`'y'`)** zurück. Krypto:
PBKDF2 (pkcs5) + AES-256/CTR, Prüfung gegen den `:c`-Wert im Methodenstring.
Kein ISDone, keine Fenster-Handles nötig.
