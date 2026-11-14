# PRESERVATION.md

Verified boot session for **Rec Room client 20260323.14** with the 2026 patch
(`Injector.exe` first, then `RecRoom.exe +forcemode:screen`).

**Verified outcome:** client boots to the title screen and authenticates as
`@scientist` against the recflare mirror (`ApiHost=ns.recflare.net`,
`ServerDomain=recflare.net`), Steam running. Evidence:
[docs/images/title-screen.png](docs/images/title-screen.png).

## What we confirmed

- Source drop used here is byte-unchanged from the client this patch fingerprints:
  `GameAssembly.dll`, `Referee.dll`, and `UnityPlayer.dll` were SHA-256 verified
  in place before the DLL was built.
- Launch order required: Steam running, then `RecRoomScreen.bat` (or start
  `Injector.exe`, then `RecRoom.exe +forcemode:screen|vr`).
- `Injector.exe` exits with a status message after failing to inject, but
  `2026patch.dll` still loads and hooks; `2026patch.log` shows
  `Native 20260323.14 patch`, `requested refresh=0 FPS`, `hooks enabled status=0`.
  The title screen still reached and the API traffic went to the mirror — the
  logged `status=0` is a success code; treat the injector's own final line as
  noisy in this test, not as evidence the DLL did not attach.

## What does not work here (and why)

A 2025-style preservation-proxy loader (game importing a fake `Referee.dll` that
tail-jumps the protector and loads patch modules in-process) **does not boot
this client**. The client crashes in the protector before the patch attaches:

```
Exception code: 0xc0000005
Fault offset: 0x000000000069839d   == RR::Methods::Referee::BootstrapInstruction
```

Any launch that does not complete the out-of-process bootstrap in `Injector.exe`
(read-instruction / read-pointer / publish-arena against
`Referee+ArenaSlot` at `0x6C10858`) faults at the same instruction. That is
a hard boundary baked into the shipped build; the game does not run without it.

The TLS callback count in the protector is zero, ruling out the TLS-init route.

## What was tried and discarded

- Proxy `Referee.dll` importing the real protector and exposing
  `GetPreserveProtector()`; the 2026 gate is `jjiEVn` (symbol relabels, not logic).
  Result: crashes at the bootstrap instruction before the module-folder loader can attach.
- Diagnosing the earlier 2025-style failure as a tamper check on the proxy was
  wrong for this build; the bootstrap protocol is the reason.

## Notes for future testing

- Configure only `ApiHost` and `ServerDomain` for the mirror; the 2026 INI
  comment block explains the semantics.
- RecRoom *must* have the marks of a Steam-prepared install because the
  client startup verifies its own state against a signature.
- Rebuild caveat: fingerprint hashes live in `RR::BuildGuard.SupportedModules`.
  Replacing any supported module (build or mirror distribution)
  is expected to fail closed until the addresses are re-derived.

## Windows Defender status

Not validated against Defender-on machines; all testing was with Defender off.

(And yes, the working assembly is still a remote-thread injector; don't mistake
a boot fix for full Antivirus compat. Both flows were kept out of this change.)
