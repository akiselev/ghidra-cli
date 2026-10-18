# 010: Bridge launch timeout kills a project's one-time language/DB upgrade

- **Reported:** 2026-10-16, CADabra machine (cadabra3 session), after upgrading Ghidra
- **CLI:** `ghidra 0.2.2` (`17e9c95`); Ghidra `12.1.4_PUBLIC`, JDK 21.0.11
- **Project:** `parasolid-re/work/ghidra-projects-kiselev/parasolid-c900fa3f430f`
  (`pskernel.dll`, 1.3 GB `.rep`, 45,246 functions), last saved by Ghidra 12.0.x/12.1.2 with
  `x86/little/64/default` language **Version 4.7**

## Symptoms

```
$ ghidra start --projects-dir .../ghidra-projects-kiselev --project parasolid-c900fa3f430f --program pskernel.dll
Starting bridge for project: .../parasolid-c900fa3f430f
Error: Ghidra bridge did not become ready within 180s: stderr: openjdk version "21.0.11" 2026-04-21
OpenJDK Runtime Environment (build 21.0.11+10)
OpenJDK 64-Bit Server VM (build 21.0.11+10, mixed mode)
```

The error does not say why. The JVM's own stdout (in `ghidra-cli.log.<date>` and
`~/.config/ghidra/ghidra_12.1.4_PUBLIC/application.log`) shows that the JVM was busy, not hung:

```
14:37:23  Opening project: .../parasolid-c900fa3f430f (HeadlessProject)
14:37:26  Sleigh compile: ... x86/data/sleighArgs.txt ...          # first use of 12.1.4's x86 spec
14:37:49  Updating language version for Program pskernel.dll: x86/little/64/default (Version 4.9) (ProgramDB)
          ... no further output ...
14:39:20  (180 s cap reached; CLI kills the process group: SIGTERM, then SIGKILL after 2 s)
14:40:14  Removing stale Ghidra lock: ...parasolid-c900fa3f430f.lock
```

Retrying with `ghidra config set launch_timeout_secs 1800` begins the same upgrade again from the
start (14:41:21 `Updating language version ... (Version 4.9)`). It ran for more than 5 minutes
with no progress output. The full duration is recorded under "Measurements" below.

## Cause

1. `start_bridge` (`src/ghidra/bridge.rs`, `poll_until_ready`) treats `launch_timeout_secs`
   (default 180 s) as an absolute cap while the child is alive. The comment says the cap is "a
   safety net, NOT the normal exit path", and it assumes launch is bounded because `-noanalysis`
   defers analysis. A language-version upgrade (and likewise a `ProgramDB` schema upgrade after a
   Ghidra version bump) runs inside `-process` program open, *before* the `-preScript` bridge binds
   its socket. It is unbounded in the same way analysis is: it re-translates every instruction of a
   large program.
2. On `TimedOut` the CLI kills the whole process group mid-upgrade. Ghidra applies the upgrade to
   the open program and persists it only on save, so the killed upgrade is lost and the next launch
   pays the full cost again. (The on-disk DB appeared intact afterwards; not yet re-validated with
   `program info`, see below.)
3. **Partly verified (see Measurements):** a successful upgrade persists only on a graceful stop. `analyzeHeadless -process`
   saves a changed program only after its scripts finish, which for the bridge means a graceful
   `ghidra stop`. A bridge that is killed, or one started for `script run --read-only`/`-readOnly`
   use, discards the upgrade, so *every* launch repeats it. Concurrent read-only bridges on the
   same project would each repeat it.
4. Nothing in the CLI recognises the situation. The failure message shows the last stderr lines
   (the JDK banner), not the stdout line that explains the delay.

## Suggested fix

- **Detect the conversion.** While waiting, scan the JVM stdout for Ghidra's upgrade markers
  (`Updating language version for Program`, `Upgrading`/`upgrade` messages from `ProgramDB` /
  `DBHandle`, and the Sleigh compile line) and switch the wait into an "upgrading" state.
  Optionally pre-detect before launch: compare the program's stored language version/DB version
  with the installed Ghidra's. The bridge could do this in a cheap `-readOnly` probe, or by reading
  the `.rep` metadata.
- **In the upgrading state, do not apply the 180 s cap.** Wait for as long as the process is alive
  (or apply a separate, much larger `upgrade_timeout_secs`, with 0 meaning unbounded). Print a
  progress line to the user: "Upgrading pskernel.dll from x86 V4.7 to V4.9 (one-time, Ghidra
  12.1.4); this can take several minutes for large programs".
- **Never SIGKILL during an upgrade.** If the user interrupts, stop gracefully and say that the
  upgrade will restart on next launch.
- **Persist the upgrade once.** After program open, if the program reports it was upgraded
  (`Program.isChanged()` immediately after open, or the open's upgrade flag), the bridge should
  `save("Language/DB upgrade to Ghidra <ver>")` before binding the socket. Refuse, or warn loudly,
  when the bridge is read-only and an upgrade is pending. Alternatively, add an explicit
  `ghidra program upgrade --project ... --program ...` command that opens writable, upgrades, saves
  and exits, and have `start` suggest it.
- **Improve the failure message.** On `TimedOut`, include the last *stdout* lines when stderr is
  only the JDK banner, and name the timeout knob (`launch_timeout_secs` /
  `GHIDRA_CLI_LAUNCH_TIMEOUT`).
- **Tests:** `poll_until_ready` already takes injected closures. Add an "upgrading" signal so that
  "alive and upgrading past the cap" returns neither `TimedOut` nor `Ready`.

## Workaround

`ghidra config set launch_timeout_secs 1800` (or `GHIDRA_CLI_LAUNCH_TIMEOUT=1800`), start once, and
`ghidra stop` gracefully so that the upgraded program is saved. Then reset the timeout.

Rescuing a launch that is already running: the cap lives only in the waiting CLI process, and
the JVM is spawned in its own process group (`process_group(0)`). `kill -KILL <ghidra start pid>`
therefore removes the cap without its kill-on-timeout cleanup, and the JVM continues. The Java
bridge rewrites the `.port`/`.pid` files itself once it binds, so later commands still find it.
(Used on run 2 at 15:02Z. Do not use SIGTERM, which may run the cleanup.)

## Measurements

- Run 1: killed at the 180 s cap, about 90 s after the upgrade began.
- Run 2 (cap 1800 s): upgrade started 14:41:21Z. At 20 min, `jstack` showed the main thread in
  `ProgramDB.<init>` → `setLanguage` → `CodeManager.reDisassembleAllInstructions`, single-threaded
  (~90% of one core, 1.5 GB RSS of an 8 GB heap), with no progress output. The cap would have
  killed it again at 15:11Z, so the CLI waiter was SIGKILLed at 15:02Z and the JVM left running.
  The upgrade finished at 15:18:40Z (**~37 min**) and the bridge was ready at 15:18:55Z.
  `program info` gave `function_count` 45,246, unchanged.
- Persistence (cause 3): a graceful `GHIDRA_CLI_SHUTDOWN_TIMEOUT=0 ghidra stop` took 4 s and logged
  `REPORT: Save succeeded for processed file: /pskernel.dll`. The next `ghidra start` with the
  default 180 s cap was ready in 40 s, with no `Updating language version` line. So a gracefully
  stopped writable bridge **does** persist the upgrade. A killed one, or a `-readOnly` one, still
  loses it (not measured). The default stop grace period was not tested here and could force-kill
  a slow save of a large upgraded DB.
- Possible progress hint (unverified): if `reDisassembleAllInstructions` walks the address space
  in order, a periodic `jstack` (or a `TaskMonitor` hooked into the open) could report the current
  address as a fraction of the program's address range.
