# netconv

[![Rust](https://img.shields.io/badge/rust-1.75+-orange.svg)](https://www.rust-lang.org)
[![WASM](https://img.shields.io/badge/wasm-wasm--bindgen-blue.svg)](https://rustwasm.github.io)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

**Vendor-agnostic network config compiler.**

netconv reads network device configurations, builds a vendor-neutral intermediate representation, and compiles it to any target platform — with an explicit, annotated report of every decision made.

```
netconv build router.cfg --target vrp
```

Like a compiler: source → IR → target. Unlike a converter: every approximation is documented, every risk is flagged, nothing is silently wrong.

**Live demo:** https://netconv.casablanque.com

---

## Why netconv

Migrating network configs between vendors is painful:

- **Manual migration** — slow, error-prone, no audit trail
- **Ansible/Terraform** — manage desired state, can't read and explain what you already have  
- **Vendor tools** — locked to their ecosystem, won't tell you what you'll lose migrating away

netconv occupies a different position: it reads your existing config, explains every translation decision, and makes every limitation explicit. A silent conversion that produces a wrong config is worse than no conversion at all.

**Primary use case:** Cisco → Huawei migration driven by import substitution requirements in Russia and CIS markets. Secondary use cases: pre-migration audit, config review, engineer onboarding.

---

## Core principle: failure is explicit

Every output element carries a confidence level:

| Level | Meaning |
|-------|---------|
| ✓ **Exact** | Guaranteed correct — direct syntactic equivalent |
| ⚠ **Approximate** | Functional equivalent with caveats — report explains what to verify |
| ✗ **Manual** | No direct equivalent — commented block with recommended approach |
| **Platform** | Vendor-specific command with no cross-platform concept |

netconv never silently drops commands. Everything unrecognised is preserved as a commented block with context.

---

## L2 and L3 are never mixed

A switch is not a router, and no one replaces one with the other. netconv treats "convert a switch config" and "convert a router config" as two different jobs, not two branches of the same function:

- **L2 profile** — VLANs, access/trunk ports, STP, voice VLAN, storm-control. Targets a switch platform (e.g. Huawei S-series).
- **L3 profile** — IP addressing, static/OSPF/BGP routing, ACLs, NAT, HSRP/VRRP. Targets a router platform (e.g. Huawei AR/NE).

You pick the profile explicitly (CLI `--profile l2|l3`, web UI tabs) — netconv never guesses it from the config's contents. If the source config contains commands from the other domain (OSPF found while converting under `--profile l2`, for example), netconv reports it explicitly instead of either rendering nonsense or quietly dropping it.

```bash
netconv --input switch.cfg  --to vrp --profile l2   # VLANs/switchport only
netconv --input router.cfg  --to vrp --profile l3   # routing/ACL/NAT only
```

This is implemented per-vendor-pair, not as a blanket rule — see the coverage table below for which pairs already enforce it (currently `ios → vrp`; `ios → eltex` doesn't filter yet).

---

## Quickstart

### Option 1 — Browser (no install)

Open [live demo](https://netconv.casablanque.workers.dev), paste config, press **convert** or `Ctrl+Enter`.

Config is processed locally in the browser via WASM — never sent to a server.

### Option 2 — Local with full WASM parser

```bash
git clone https://github.com/casablanque-code/netconv.git
cd netconv

# Build WASM
cargo install wasm-pack
wasm-pack build crates/netconv-wasm --target web --out-dir ../../web/wasm --release

# Serve locally
python3 -m http.server 8080 --directory web/

# Open http://localhost:8080
# "demo mode" badge disappears — full Rust parser active
```

> **WSL:** ports forward automatically in WSL2. Use `http://localhost:8080` in Windows browser.

### Option 3 — CLI

```bash
cargo build --release -p netconv

# Convert (stdout)
./target/release/netconv --input router.cfg --from ios --to vrp

# Convert with explicit device profile — filters L2 vs L3 domain (see below)
./target/release/netconv --input switch.cfg --to vrp --profile l2
./target/release/netconv --input router.cfg --to vrp --profile l3

# Write to file
./target/release/netconv --input router.cfg --to vrp --output router_vrp.cfg

# Show warnings and manual items
./target/release/netconv --input router.cfg --warnings

# Full report as JSON (for scripts / CI gates)
./target/release/netconv --input router.cfg --json > report.json
```

---

## CI/CD integration

Use netconv as a network config linter in your pipeline:

```bash
# Fail pipeline if any manual intervention required
./netconv --input router.cfg --json | jq '.report.manual_required == 0'

# Fail if coverage drops below threshold
./netconv --input router.cfg --json | jq '.report.coverage_pct >= 95'
```

---

## Supported conversions

| Source | Target | L2 profile | L3 profile |
|--------|--------|------------|------------|
| Cisco IOS | Huawei VRP | ✓ Implemented (S-series) | ✓ Implemented (AR/NE) |
| Cisco IOS | Eltex ESR | 🚧 Planned (MES) | 🚧 In progress (not domain-filtered yet) |
| Cisco IOS | VyOS | 🚧 Planned | 🚧 Planned |
| Cisco ASA | — | n/a (ASA has no L2 role) | 🚧 Planned |

`--profile` without a value (legacy `VrpRenderer`, or any `--to eltex` call) still renders everything unfiltered — that's the "useless L2↔L3 converter" this project is actively moving away from, kept only for backward compatibility until every pair is split.

---

## Coverage: Cisco IOS → Huawei VRP

### System
| Feature | Status | Notes |
|---------|--------|-------|
| hostname | ✓ Exact | → sysname |
| NTP server | ✓ Exact | → ntp-service unicast-server |
| SNMP community | ✓ Exact | → snmp-agent community |
| SNMP reserved name conflict | ⚠ Manual | e.g. community "write" conflicts with VRP keyword |
| Logging buffered | ⚠ Approx | → info-center logbuffer size |
| SSH version | ⚠ Approx | → stelnet server enable |
| line vty exec-timeout | ⚠ Approx | → user-interface vty / idle-timeout |
| line vty transport input | ⚠ Approx | → protocol inbound |
| username + privilege | ✗ Manual | → local-user (password cannot be migrated) |
| enable secret | ✗ Manual | No VRP equivalent — AAA config required |
| aaa new-model | ✗ Manual | → authentication-scheme + domain |
| ip http server | ✗ Manual | → http server enable / undo |

### VLAN & STP
| Feature | Status | Notes |
|---------|--------|-------|
| vlan batch | ⚠ Approx | Auto-collected from all interface references |
| vlan name | ⚠ Approx | → description |
| spanning-tree mode rapid-pvst | ✗ Manual | **HIGH RISK** → rstp (one tree vs per-VLAN). MSTP starting point auto-generated |
| spanning-tree loopguard | ⚠ Approx | → stp loop-protection |
| spanning-tree portfast | ⚠ Approx | → stp edged-port enable |
| spanning-tree bpduguard | ⚠ Approx | → stp bpdu-protection |
| spanning-tree bpdufilter (access) | ⚠ Approx | → stp bpdu-filter enable |
| spanning-tree bpdufilter (trunk) | ✗ Manual | **RISK** — not auto-applied on trunk ports |
| spanning-tree vlan priority | ✗ Manual | No per-VLAN priority in RSTP |

### Interfaces
| Feature | Status | Notes |
|---------|--------|-------|
| ip address | ✓ Exact | |
| shutdown / no shutdown | ✓ Exact | → shutdown / undo shutdown |
| description | ✓ Exact | |
| switchport access vlan | ⚠ Approx | → port default vlan |
| switchport trunk allowed | ⚠ Approx | → port trunk allow-pass vlan |
| switchport voice vlan (access) | ⚠ Approx | → voice-vlan X enable + global voice-vlan enable |
| switchport voice vlan (trunk) | ⚠ Warn | Non-standard — applied with warning |
| storm-control level | ⚠ Approx | → percent (assumption flagged inline) |
| ip helper-address | ⚠ Approx | → dhcp relay server-ip |
| ip access-group | ⚠ Approx | → traffic-filter |
| ip nat inside/outside | ⚠ Approx | NAT moves to interface context |

### Routing
| Feature | Status | Notes |
|---------|--------|-------|
| ip default-gateway | ⚠ Approx | → ip route-static 0.0.0.0/0 |
| ip route (static) | ⚠ Approx | → ip route-static, AD → preference |
| OSPF process | ⚠ Approx | network inside area, log-peer-change |
| OSPF redistribute | ⚠ Approx | → import-route |
| OSPF passive-interface | ⚠ Approx | → silent-interface |
| BGP neighbors | ⚠ Approx | neighbor → peer, remote-as → as-number |
| BGP peer-groups | ⚠ Approx | → peer-group NAME |
| BGP address-family | ⚠ Approx | → ipv4-family unicast |
| BGP route-map | ⚠ Approx | → route-policy import/export |
| BGP next-hop-self | ⚠ Approx | → next-hop-local |
| HSRP → VRRP | ⚠ Approx | Protocols incompatible at wire level — MAC differs |
| HSRP track | ✗ Manual | → NQA/BFD required |
| EIGRP | ✗ Manual | Cisco proprietary — not supported on VRP |

### ACL & NAT
| Feature | Status | Notes |
|---------|--------|-------|
| ip access-list named/numbered | ⚠ Approx | acl name, rule, numbering remapped |
| NAT overload (PAT) | ⚠ Approx | → nat outbound on interface |
| NAT static | ⚠ Approx | Reversed global/inside order |

---

## Architecture

```
crates/
  netconv-core/        # Vendor-neutral IR, ConfigParser/ConfigRenderer traits, ConversionReport,
                        #   profile.rs — DeviceProfile (L2Switch/L3Router) + domain mismatch detection
  netconv-parser-ios/  # Cisco IOS parser: pass1 structural tree, pass2 semantic analysis
  netconv-render-vrp/  # Huawei VRP renderer — VrpL2Renderer / VrpL3Renderer (domain-filtered) +
                        #   legacy VrpRenderer (unfiltered, kept for backward compat)
  netconv-render-eltex/# Eltex ESR renderer — not yet split into l2/l3
  netconv-wasm/        # WASM bindings (wasm-bindgen): convert_config (legacy) + convert_config_profiled
cli/                   # CLI binary (clap) — --profile l2|l3
web/
  index.html           # Single-file UI: L2/L3 tabs, WASM auto-load, demo fallback
  worker.js             # Cloudflare Worker
```

### Adding a new target vendor

One new crate, implement `ConfigRenderer`. Parser and IR are untouched. If the platform has distinct switch and router product lines (most do — that's the point), split the renderer into two structs from the start rather than adding a "convert everything" renderer that has to be un-mixed later:

```rust
pub struct FooL2Renderer; // switch: VLANs, switchport, STP
pub struct FooL3Renderer; // router: addressing, routing, ACL, NAT

impl ConfigRenderer for FooL3Renderer {
    fn render(&self, config: &NetworkConfig, report: &mut ConversionReport) -> Result<String, _> {
        // render only L3-relevant IR fields to Foo router syntax
    }
    fn vendor_name(&self) -> &str { "Foo Router" }
}
```

Register both in `netconv-wasm/src/lib.rs::run_conversion_profiled` and in `cli/src/main.rs`'s profile match arms. Add to the web UI's `dst-vendor` select, gated per-profile the same way `updateVendorOptionsForProfile()` already gates Eltex for L2.

See `crates/netconv-render-vrp/src/scope.rs` for the pattern used to share code between the two renderers where a vendor's switch and router syntax overlap (e.g. common system settings).

---

## Embedded expertise

netconv encodes cross-vendor knowledge that engineers learn the hard way:

- **HSRP → VRRP**: protocols are wire-incompatible. MAC address changes from `0000.0c07.acXX` to `0000.5e00.01XX`. All nodes must be migrated simultaneously.
- **rapid-pvst → rstp**: Cisco runs a separate STP tree per VLAN. Huawei RSTP runs one tree for all VLANs. Topology can change silently if different VLANs had different root bridges.
- **BPDU filter on trunk**: context-aware — not applied automatically on trunk ports where it can cause loops.
- **SNMP community name conflicts**: VRP reserves `read`, `write`, `trap` as keywords — using them as community names produces ambiguous syntax.
- **storm-control level**: Cisco `level` units vary by platform (%, pps, kbps). Every generated command is flagged with an explicit assumption.

---

## Requirements

| Component | Version | When needed |
|-----------|---------|-------------|
| Rust | 1.75+ | always |
| wasm-pack | 0.13+ | WASM build only |
| Python 3 | any | local HTTP server only |
| Node.js | 18+ | Cloudflare Workers deploy only |

Install Rust: https://rustup.rs  
Install wasm-pack: `cargo install wasm-pack`

---

## Tests

```bash
cargo test                        # all tests
cargo test -p netconv-parser-ios  # parser only (12 tests)
```

---

## License

MIT
