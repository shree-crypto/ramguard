# Third-party software and references

RamGuard's Rust implementation uses these crates. No crate source is copied or vendored in this repository.

| Crate | Version | License | Source |
|---|---:|---|---|
| clap | 4.6.7 | MIT OR Apache-2.0 | [crates.io](https://crates.io/crates/clap/4.6.7), [source](https://github.com/clap-rs/clap) |
| serde | 1.0.229 | MIT OR Apache-2.0 | [crates.io](https://crates.io/crates/serde/1.0.229), [source](https://github.com/serde-rs/serde) |
| serde_json | 1.0.154 | MIT OR Apache-2.0 | [crates.io](https://crates.io/crates/serde_json/1.0.154), [source](https://github.com/serde-rs/json) |
| windows-sys | 0.61.2 | MIT OR Apache-2.0 | [crates.io](https://crates.io/crates/windows-sys/0.61.2), [windows-rs source and license](https://github.com/microsoft/windows-rs) |

The following projects were reviewed only as high-level product references. RamGuard does not bundle them, copy their code, or derive an unsafe RAM-purge implementation from them.

| Project | License | Reference |
|---|---|---|
| BleachBit | GPL-3.0 | [source](https://github.com/bleachbit/bleachbit) |
| Mem Reduct | GPL-3.0 | [source](https://github.com/henrypp/memreduct) |
| Czkawka | MIT | [source](https://github.com/qarmin/czkawka) |
| System Informer | MIT | [source](https://github.com/winsiderss/systeminformer) |

The executable has no PowerShell runtime dependency.
