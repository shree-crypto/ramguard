# RamGuard

A small, native Rust CLI for Windows memory diagnosis and guarded process/cache cleanup. No scripting runtime, resident service, or telemetry.

```powershell
ramguard status
ramguard preview --json
ramguard clean
ramguard cache preview
ramguard cache clean
```

## What it does

- Shows physical memory, commit usage, kernel pools, and the largest application groups.
- Automatically closes only verified, old, known orphan helper leaves.
- Offers a numbered chooser for additional apps, with graceful closure first and explicit confirmation before forced closure.
- Rechecks process identity and ownership, protects current-session ancestors and shared backends, and reports restarting tools.
- Cleans a fixed cache catalog with age, identity, reparse-point, active-build, and held-handle checks.
- Saves sanitized local reports and retains 30 recognized report files.

Working sets can share pages; adding application totals does not explain all physical RAM. RamGuard does not purge standby memory, trim working sets, disable startup items, or promise a fixed amount of RAM recovery.

## Build and install

Windows x64 and a Rust Windows toolchain with its linker are required. MSVC needs Microsoft's C++ Build Tools; GNU needs compatible binutils.

```powershell
git clone https://github.com/shree-crypto/ramguard.git
cd ramguard
cargo test --locked
cargo install --path . --locked
```

Or build without installing:

```powershell
cargo build --release --locked
.\target\release\ramguard.exe status
```

Cargo honors `CARGO_TARGET_DIR`. `build.ps1` provides a thin optional build/test wrapper without machine-specific paths.

On the original development laptop, three release status runs took 505–519 ms and reported 11.43–11.56 MiB of tool working set. The executable was about 2.34 MiB. These are small observed samples, not peak-memory or universal performance guarantees.

## Commands

| Command | Behaviour |
|---|---|
| `status` | Memory counters and ten largest application groups |
| `preview` | Process classifications; no changes |
| `clean` | Verified automatic cleanup, then the app chooser |
| `doctor` | Memory counters and tool/supervisor relationships |
| `cache preview` | Eligible cache locations and logical-size estimates |
| `cache clean` | Preview and choose cache locations to clean |

`--json` produces structured output. JSON cleanup requires `--yes` and never prompts. For process cleanup, `--yes` skips manual app selection; it does not force-close arbitrary apps. Legacy `-Json` and `-Yes` flags are accepted.

```powershell
ramguard clean --yes --json
ramguard cache clean --yes --json --only npmCache,pipCache
```

The chooser accepts comma-separated row numbers, `more` to page, or Enter to skip. Forced closure requires typing `FORCE` and can lose unsaved work. Process cleanup includes observations after three and ten seconds to detect restarts.

## Cleanup boundaries

The default catalog contains only the current user's Local Temp, npm cache, and pip cache. Files must be older than 24 hours. Windows Temp, source projects, installed packages, Codex runtimes/history, credentials, pagefile, and hibernation files are excluded.

Changed, locked, redirected, inaccessible, or uncertain targets are skipped. Windows services, recognized security processes, foreign/unknown owners, shared Codex/ChatGPT backends, current-session ancestors, and an identified M5 companion are protected. Low CPU alone never proves idleness. There is no reliable idle-chat lifecycle adapter; uncertain tools remain protected/manual.

Reports stay under `%LOCALAPPDATA%\RamGuard\reports`. Full process command lines and conversation content are not serialized. `FreeCBytes` is an optional C-drive metric; unavailable counters remain null.

### Optional M5 tools profile

The `m5-tools` build feature adds three optional cache locations for the original robot-tool layout under `X:\M5RobotTools`: PlatformIO cache and two Arduino build directories. This feature is disabled by default. Missing locations are skipped; an X: drive is not required for normal use.

```powershell
cargo build --release --locked --features m5-tools
```

## Tests

```powershell
cargo fmt --all -- --check
cargo test --locked
cargo test --locked --features m5-tools
```

Tests cover PID reuse, uncertain owners, protected ancestry, critical-process guards, a disposable child process, cache locks/identity changes, directory sharing, junctions, report redaction/retention, and compiled CLI JSON contracts.

Two live cleanup checks are ignored by default. They exercise actual automatic process cleanup and the fixed npm cache entry; run them only when intentional:

```powershell
cargo test --locked --test cli live_ -- --ignored --test-threads=1
```

## Open-source building blocks

RamGuard uses [Microsoft Windows bindings](https://github.com/microsoft/windows-rs), [Clap](https://github.com/clap-rs/clap), and [Serde](https://github.com/serde-rs/serde). [Third-party notes](THIRD_PARTY.md) document versions, licenses, and the cleanup projects reviewed. Dependency license texts are retained in [THIRD_PARTY_LICENSES.txt](THIRD_PARTY_LICENSES.txt).

## License

RamGuard's own code is licensed under **GNU GPL version 3 only (`GPL-3.0-only`)**. See [LICENSE](LICENSE). Third-party dependencies retain their own notices and licenses.
