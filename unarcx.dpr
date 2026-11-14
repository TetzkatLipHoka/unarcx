program unarcx;
{$APPTYPE CONSOLE}
{
  unarcx - drive an Inno/ISDone repack's own 32-bit unarc.dll (FreeArc) to
  extract an encrypted FreeArc archive, WITHOUT running the installer and
  WITHOUT the ISDone GUI layer.

  Why this works (reverse-engineered from the shipped unarc.dll, IDA 9.1):
    * export ordinal 2 = FreeArcExtract(callback, cmd1, cmd2, ..., NULL)   __cdecl
      - args mirror the unarc command line; the list ends at the first NULL
        or empty string. argv[0] is hard-set internally to "c:\unarc.dll".
    * FreeArcExtract sets its internal "encryption enabled" flag to
      (callback != NULL), so passing a callback is what unlocks the password
      path. For every step it calls: callback(what, int1, int2, str)  __stdcall
      (convention per the official unarcdll.h; FreeArc's own InnoSetup example
       wraps it as stdcall too).
    * When a block is encrypted it emits  what="password?"  with
      int1 = buffer size (2000) and str = the buffer the DLL then reads the
      password from. The callback must copy the password into str and return
      121 ('y') to proceed; 113 ('q') / anything else => "wrong password" (-13).
      Crypto path is PBKDF2 (pkcs5) + AES-256/CTR, check against the ':c' value.

  Run it FROM the folder that contains the repack's unarc.dll, arc.ini,
  cls.ini and the cls-*.dll / cls-*.exe / srep64.exe codec plugins (they are
  loaded by name from the current directory). Do this in a throwaway VM:
  unarc.dll and the codec binaries are untrusted scene code.

  usage: unarcx <archive> <outdir> <password> [mask ...]
}

uses
  Winapi.Windows, System.SysUtils;

const
  CB_CONTINUE = 0;
  CB_PW_YES   = 121;   // 'y' : password supplied, retry/accept
  // 113 = 'q' would mean "give up / wrong password"

// The lolz / srep codec workers exchange data over Global\ named file mappings,
// which need SeCreateGlobalPrivilege -> an elevated (admin) process. The repack
// installer runs elevated; a normal console does not, so without elevation the
// workers fail with "Can't create/open ... mapping!". Warn up front.
function IsUserAnAdmin: BOOL; stdcall; external 'shell32.dll' name 'IsUserAnAdmin';

var
  gPassword: AnsiString;

// __stdcall callback invoked by FreeArcExtract for every event.
function ArcCallback(what: PAnsiChar; int1, int2: Integer; str: PAnsiChar): Integer; stdcall;
var
  w: AnsiString;
  n: Integer;
begin
  w := AnsiString(what);

  if w = 'password?' then
  begin
    n := Length(gPassword);
    if (int1 > 0) and (n > int1 - 1) then n := int1 - 1;   // never exceed the DLL's buffer
    if (str <> nil) then
    begin
      if n > 0 then Move(gPassword[1], str^, n);
      str[n] := #0;
    end;
    Result := CB_PW_YES;
    Exit;
  end;

  if w = 'filename' then
    Writeln('  ', AnsiString(str))
  else if w = 'write' then
    Write(#13'  ... ', int1, ' MB written');

  Result := CB_CONTINUE;
end;

type
  // Fixed-arity view of the __cdecl varargs export; unused slots pass NULL,
  // which also terminates the DLL's argument scan.
  TFreeArcExtract = function(cb: Pointer;
    c01, c02, c03, c04, c05, c06, c07, c08, c09, c10,
    c11, c12, c13, c14, c15, c16, c17, c18, c19, c20,
    c21, c22, c23, c24: PAnsiChar): Integer; cdecl;

var
  h: HMODULE;
  FreeArcExtract: TFreeArcExtract;
  args: array[0..23] of AnsiString;
  p: array[0..23] of PAnsiChar;
  i, argn, rc: Integer;

  procedure AddArg(const s: AnsiString);
  begin
    if argn > High(args) then
      raise Exception.Create('too many command arguments (max 24)');
    args[argn] := s;
    Inc(argn);
  end;

begin
  if ParamCount < 3 then
  begin
    Writeln('unarcx - extract an encrypted FreeArc archive via the repack''s own unarc.dll');
    Writeln('usage: unarcx <archive> <outdir> <password> [mask ...]');
    Writeln('Run from the folder holding unarc.dll + arc.ini + cls.ini + the codec plugins.');
    Halt(2);
  end;

  gPassword := AnsiString(ParamStr(3));

  h := LoadLibraryA('unarc.dll');
  if h = 0 then
  begin
    Writeln('ERROR: cannot load unarc.dll from the current directory (GetLastError=', GetLastError, ')');
    Halt(3);
  end;
  @FreeArcExtract := GetProcAddress(h, 'FreeArcExtract');
  if not Assigned(FreeArcExtract) then
  begin
    Writeln('ERROR: export FreeArcExtract not found in unarc.dll');
    Halt(3);
  end;

  argn := 0;
  AddArg('x');                                   // extract with stored paths
  AddArg('-o+');                                 // overwrite existing
  AddArg('-dp' + AnsiString(ParamStr(2)));       // destination dir (glued)
  if FileExists('arc.ini') then
    AddArg('-cfg' + AnsiString(ExpandFileName('arc.ini')));  // external-codec map
  AddArg('--');                                  // end of options
  AddArg(AnsiString(ParamStr(1)));               // archive
  for i := 4 to ParamCount do                    // optional file masks
    AddArg(AnsiString(ParamStr(i)));

  for i := 0 to High(p) do
    if i < argn then p[i] := PAnsiChar(args[i]) else p[i] := nil;

  if not IsUserAnAdmin then
    Writeln('WARNING: not elevated. The lolz/srep workers use Global\ shared memory '#13#10 +
            '         and need admin rights. If you get "Can''t create/open ... mapping!",'#13#10 +
            '         re-run this from an Administrator console.');

  Writeln('Extracting "', ParamStr(1), '" -> "', ParamStr(2), '"');
  rc := FreeArcExtract(@ArcCallback,
    p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7], p[8], p[9],
    p[10], p[11], p[12], p[13], p[14], p[15], p[16], p[17], p[18], p[19],
    p[20], p[21], p[22], p[23]);

  Writeln;
  Write('FreeArcExtract returned ', rc, ' -> ');
  case rc of
    0:    Writeln('OK');
   -1:    Writeln('broken archive or not enough disk space');
   -13:   Writeln('WRONG PASSWORD');
  -127:   Writeln('cancelled');
  else    Writeln('error');
  end;

  Halt(rc);
end.
