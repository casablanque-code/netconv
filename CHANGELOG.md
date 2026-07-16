# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
versioning follows [SemVer](https://semver.org/) once the public API
(CLI flags, `--profile` values, WASM exports) is considered stable —
before 1.0.0, minor version bumps may still contain breaking changes.

## [Unreleased]

## [0.3.0] — 2026-07-17

### Added

- Web UI: split-diff view. Toggles both panes into a read-only,
  line-annotated mode; clicking a flagged line highlights the
  corresponding line(s) on the other side and shows a popover with the
  report message — linked by shared `ReportItem` index (not line
  numbers, which the report doesn't track), matched against
  `source_snippet`/`target_snippet` text.
- CI: `release.yml` — pushing a `v*` tag builds the CLI for
  linux/macos(x86_64+aarch64)/windows and publishes a GitHub Release
  with the binaries attached.
- CI: `prepare-release.yml` — the only manual step left in cutting a
  release. `Actions → Prepare Release → Run workflow`, type a version;
  it bumps the version, commits, tags, and pushes, which triggers
  `release.yml` automatically.
- CI: `rebuild-wasm.yml` — rebuilds the committed `web/wasm/*.wasm`
  binary from source on every push to `main` touching a WASM-feeding
  crate, and commits the result back. `web/wasm/` is a checked-in build
  artifact, not something generated at deploy time — without this,
  fixes to the parser/renderers were correct in source but invisible on
  the live site (Cloudflare's git integration just deploys whatever is
  already committed) until someone remembered to rebuild by hand.

### Changed

- All crate versions now come from a single `[workspace.package]
  version` in the root `Cargo.toml` via `version.workspace = true`,
  instead of being duplicated (and drifting) across seven files.
- `netconv-wasm`'s `[profile.release]` moved to the workspace root —
  this also silences the `cargo check` warning about per-package
  profiles being ignored outside the workspace root.
- Web UI: brighter `.pane-action` buttons (were nearly invisible —
  `var(--text3)` on `var(--border)`), header no longer overflows
  un-wrapped below ~1100px width, report panel is resizable by
  dragging its top edge instead of a fixed 280px cap.
- Web UI: L2 is now the default profile tab (was L3), and the active
  profile tab is styled red — it changes what actually gets rendered,
  not just a display filter, so it's deliberately more prominent than
  the report's severity filter buttons, which share the same base class
  but keep their neutral styling.

### Fixed

- Report accuracy: `source_snippet` for `interface.description`,
  `interface.shutdown`, `interface.mtu`, `interface.speed`,
  `interface.duplex`, `interface.l2` (access/trunk), `ospf.interface`,
  `ospf.cost`, `ospf.timers`, `stp.portfast`, `stp.bpduguard`, and
  `stp.guard_root` used to show the bare interface name (e.g.
  `interface GigabitEthernet0/1`) as "before" instead of the actual
  source command (e.g. `description ...`), while still being labeled an
  exact match. Affected `VrpRenderer`/`VrpL2Renderer`/`VrpL3Renderer`
  and both Eltex renderers. Fixed across all three files; regression
  test added (`report_snippet_accuracy.rs`) so this can't silently
  regress.

## [0.2.0] — 2026-07-15

### Added

- Web UI: file upload (drag-and-drop + file picker) for the source
  config, and downloading the result as `<hostname>-<vendor>.cfg` plus
  a readable Markdown conversion report alongside it.

## [0.1.0] — 2026-07-14

First tagged release. Core theme of this release: **L2 and L3 are never
mixed** — a switch config and a router config are two different jobs,
not two branches of the same renderer.

### Added

- `netconv-core::profile` — `DeviceProfile` (`L2Switch` / `L3Router`) and
  `detect_domain_mismatches()`, which flags IR content belonging to the
  other domain (VLAN/switchport under an L3 profile, OSPF/BGP/ACL/NAT/HSRP
  under an L2 profile) without silently rendering or dropping it.
- `VrpL2Renderer` / `VrpL3Renderer` — Huawei VRP output split by device
  role: S-series (switch) vs AR/NE (router). First vendor pair with full
  domain filtering.
- `EltexL2Renderer` / `EltexL3Renderer` — same split for Eltex: MES
  (switch) vs ESR (router/firewall). Replaces the previous single
  `EltexRenderer`, which used to silently comment out L2 commands
  ("Eltex ESR is a router/firewall, not a managed switch...") instead of
  having anywhere else to put them.
- CLI: `--profile l2|l3` flag. For `ios→vrp` and `ios→eltex` it now
  filters the rendered output by domain, not just warns about it.
- WASM: `convert_config_profiled(config, source, target, profile)`
  export, alongside the original `convert_config` (unchanged, kept for
  backward compatibility).
- Web UI: L2 (switching) / L3 (routing) tabs above the vendor selects.
  Switching tabs relabels the VRP/Eltex target options to match the
  actual target platform (S-series/AR-NE, MES/ESR) and re-runs
  conversion through the profile-aware WASM export when available,
  degrading through old WASM export → demo mode if not.
- CI: GitHub Actions running `cargo check` and `cargo test` on every
  push/PR. `cargo clippy` and `cargo fmt --check` run as informational
  (non-blocking) jobs for now — the codebase hasn't been run through
  either yet.

### Changed

- `VrpRenderer` and `EltexRenderer` (the original, undifferentiated
  renderers) are kept as-is for backward compatibility with any script
  calling `convert()` without a profile. New integrations should prefer
  the `*L2Renderer` / `*L3Renderer` pair for the vendor they target.
- README: new "L2 and L3 are never mixed" section, per-profile coverage
  table, updated architecture diagram and "adding a new vendor" guide
  (now nudges toward an L2/L3 split from the start instead of a
  render-everything renderer).

### Known limitations

- Domain filtering is implemented per vendor pair, not universally:
  `ios → vrp` and `ios → eltex` filter; anything using the legacy
  unprofiled renderers does not.
- Eltex MES VLAN-entry syntax is confirmed for the MES23xx/33xx/53xx
  family; MES14xx/24xx use a different VLAN-creation flow. Every VLAN
  item in the report is marked Approximate, not Exact, for this reason.
- Web UI demo mode (used when WASM isn't loaded) does not filter by
  profile — it always renders the full, unfiltered output.
