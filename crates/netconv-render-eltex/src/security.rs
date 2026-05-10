use netconv_core::ir::*;
use netconv_core::report::{ConversionReport, RiskLevel, ConfidenceLevel};

#[derive(Debug, Clone)]
pub struct ZoneClassification {
    pub zone: ZoneName,
    pub confidence: ConfidenceLevel,
    pub reason: String,
    pub role: InterfaceRole,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ZoneName { Lan, Wan, Unknown }

impl ZoneName {
    pub fn as_str(&self) -> &str {
        match self { ZoneName::Wan => "WAN", ZoneName::Lan => "LAN", ZoneName::Unknown => "UNSET" }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum InterfaceRole {
    WanUplink,
    ManagementSuspected,
    AccessEndpoint { vlan: Option<u16> },
    TrunkInterswitch,
    Loopback,
    Unknown,
}

impl InterfaceRole {
    pub fn label(&self) -> &str {
        match self {
            InterfaceRole::WanUplink             => "WAN uplink",
            InterfaceRole::ManagementSuspected   => "management (suspected)",
            InterfaceRole::AccessEndpoint { .. } => "access endpoint",
            InterfaceRole::TrunkInterswitch      => "trunk/inter-switch",
            InterfaceRole::Loopback              => "loopback",
            InterfaceRole::Unknown               => "unclassified",
        }
    }
    pub fn access_vlan(&self) -> Option<u16> {
        if let InterfaceRole::AccessEndpoint { vlan } = self { *vlan } else { None }
    }
}

pub fn classify_zone(iface: &Interface, cfg: &NetworkConfig) -> ZoneClassification {
    if iface.nat_direction == Some(NatDirection::Outside) {
        return ZoneClassification { zone: ZoneName::Wan, confidence: ConfidenceLevel::High,
            reason: "nat outside configured".to_string(), role: InterfaceRole::WanUplink };
    }
    if let Some(desc) = &iface.description {
        let d = desc.to_lowercase();
        for kw in &["uplink","wan","isp","internet","external","provider","upstream","transit","peering"] {
            if d.contains(kw) {
                return ZoneClassification { zone: ZoneName::Wan, confidence: ConfidenceLevel::High,
                    reason: format!("description contains '{}'", kw), role: InterfaceRole::WanUplink };
            }
        }
    }
    for route in &cfg.routing.static_routes {
        if route.prefix.to_string() == "0.0.0.0/0" {
            if let Some(addr) = iface.addresses.first() {
                if let NextHop::Ip(nh) = &route.next_hop {
                    if addr.prefix.contains(nh) {
                        let is_vlan1 = matches!(&iface.name.kind, InterfaceKind::Vlan) && iface.name.id == "1";
                        return ZoneClassification {
                            zone: ZoneName::Wan, confidence: ConfidenceLevel::Medium,
                            reason: if is_vlan1 { "default route via VLAN1 — likely management".to_string() }
                                    else { "default route next-hop on this interface".to_string() },
                            role: if is_vlan1 { InterfaceRole::ManagementSuspected } else { InterfaceRole::WanUplink },
                        };
                    }
                }
            }
        }
    }
    if iface.name.kind == InterfaceKind::Loopback {
        return ZoneClassification { zone: ZoneName::Lan, confidence: ConfidenceLevel::High,
            reason: "loopback interface".to_string(), role: InterfaceRole::Loopback };
    }
    if let Some(l2) = &iface.l2 {
        return match l2.mode {
            L2Mode::Trunk => ZoneClassification { zone: ZoneName::Unknown, confidence: ConfidenceLevel::Low,
                reason: "trunk port — cannot determine zone automatically".to_string(),
                role: InterfaceRole::TrunkInterswitch },
            L2Mode::Access => ZoneClassification { zone: ZoneName::Unknown, confidence: ConfidenceLevel::Low,
                reason: format!("access port{}", l2.access_vlan.map(|v| format!(" VLAN {}", v)).unwrap_or_default()),
                role: InterfaceRole::AccessEndpoint { vlan: l2.access_vlan } },
        };
    }
    ZoneClassification { zone: ZoneName::Unknown, confidence: ConfidenceLevel::Low,
        reason: "no classification signals".to_string(), role: InterfaceRole::Unknown }
}

pub fn render_security_zones(cfg: &NetworkConfig, out: &mut Vec<String>, report: &mut ConversionReport) {
    let cls: Vec<(&Interface, ZoneClassification)> = cfg.interfaces.iter()
        .map(|i| (i, classify_zone(i, cfg))).collect();

    let has_wan    = cls.iter().any(|(_, z)| z.zone == ZoneName::Wan);
    let unknown_ct = cls.iter().filter(|(_, z)| z.zone == ZoneName::Unknown).count();
    let access_ct  = cls.iter().filter(|(_, z)| matches!(z.role, InterfaceRole::AccessEndpoint { .. })).count();
    let trunk_ct   = cls.iter().filter(|(_, z)| z.role == InterfaceRole::TrunkInterswitch).count();
    let med_wan_ct = cls.iter().filter(|(_, z)| z.zone == ZoneName::Wan && z.confidence == ConfidenceLevel::Medium).count();

    compute_risk_score(cfg, &cls, report);
    let risk_snapshot = report.risk.clone();

    // ─────────────────────────────────────────────────────────────────
    // SECTION 1: ANALYSIS
    // ─────────────────────────────────────────────────────────────────
    out.push("! ╔══════════════════════════════════════════════════════════════════╗".to_string());
    out.push("! ║  SECTION 1: PRE-MIGRATION ANALYSIS                             ║".to_string());
    out.push("! ╚══════════════════════════════════════════════════════════════════╝".to_string());
    out.push(String::new());

    render_architecture_summary(cfg, &cls, &risk_snapshot, out);
    render_change_risk_score(&risk_snapshot, out);
    render_migration_complexity(cfg, &cls, out);
    render_top_risks(cfg, med_wan_ct, out);
    render_confidence_by_area(&cls, cfg, out);
    render_inference_table(&cls, unknown_ct, access_ct, trunk_ct, out);
    render_config_validity_status(cfg, &cls, unknown_ct, out);

    // ─────────────────────────────────────────────────────────────────
    // SECTION 2: CONFIG (только то что ВАЛИДНО)
    // ─────────────────────────────────────────────────────────────────
    out.push("! ╔══════════════════════════════════════════════════════════════════╗".to_string());
    out.push("! ║  SECTION 2: GENERATED CONFIG                                   ║".to_string());
    out.push("! ║  STATUS: INCOMPLETE — see CONFIG STATUS above before applying  ║".to_string());
    out.push("! ╚══════════════════════════════════════════════════════════════════╝".to_string());
    out.push(String::new());

    // Zone declarations — только known zones
    out.push("! Known security zones:".to_string());
    out.push("security zone LAN".to_string());
    out.push(" exit".to_string());
    if has_wan {
        out.push("security zone WAN".to_string());
        out.push(" exit".to_string());
    }
    if unknown_ct > 0 {
        out.push(format!("! {} zones NOT declared — assign manually before adding interfaces", unknown_ct));
        out.push("! Example: security zone VLAN10_USERS / security zone VLAN18_CAMERAS".to_string());
    }
    out.push(String::new());

    // SECTION 3: ACTION PLAN (manual actions)
    out.push("! ╔══════════════════════════════════════════════════════════════════╗".to_string());
    out.push("! ║  SECTION 3: ACTION PLAN                                        ║".to_string());
    out.push("! ╚══════════════════════════════════════════════════════════════════╝".to_string());
    out.push(String::new());
    render_manual_actions_summary(cfg, &cls, out);

    // SECTION 4: FIREWALL (safe mode — только комментарии)
    out.push("! ╔══════════════════════════════════════════════════════════════════╗".to_string());
    out.push("! ║  SECTION 4: FIREWALL POLICY                                    ║".to_string());
    out.push("! ╚══════════════════════════════════════════════════════════════════╝".to_string());
    out.push(String::new());
    render_firewall_safe_mode(cfg, out, report);

    // Report — минимальный, без per-interface шума
    if unknown_ct > 0 {
        report.add_manual("security_zones",
            &format!("{} interfaces unassigned", unknown_ct),
            &format!("{} interfaces require manual zone assignment (see SECTION 1: INFERENCE)", unknown_ct),
            Some("Assign zones, then uncomment security-zone lines in interface blocks"));
    }
    for (iface, z) in cls.iter().filter(|(_, z)| z.zone == ZoneName::Wan) {
        match z.confidence {
            ConfidenceLevel::High => report.add_approximate("security_zone.wan",
                &format!("interface {}", iface.name.original), "WAN",
                &format!("WAN [HIGH]: {}", z.reason)),
            _ => report.add_manual("security_zone.wan.uncertain",
                &format!("interface {}", iface.name.original),
                &format!("WAN [MEDIUM]: {} — verify topology", z.reason),
                Some("May be management interface")),
        }
    }
}

fn render_change_risk_score(risk: &netconv_core::report::RiskScore, out: &mut Vec<String>) {
    // Числовой score из reasons
    let score: u32 = risk.reasons.iter().map(|r| {
        if r.contains("L2 switch") { 40 }
        else if r.contains("VLANs →") { 20 }
        else if r.contains("STP") { 15 }
        else if r.contains("firewall") { 10 }
        else if r.contains("uncertain WAN") { 15 }
        else { 5 }
    }).sum::<u32>().min(100);

    out.push("! ── CHANGE RISK SCORE ────────────────────────────────────────────────".to_string());
    out.push(format!("!   Score: {} / 100  [{}]", score, risk.level.label()));
    out.push("!   Breakdown:".to_string());
    for r in &risk.reasons {
        let pts = if r.contains("L2 switch") { 40 }
            else if r.contains("VLANs →") { 20 }
            else if r.contains("STP") { 15 }
            else if r.contains("uncertain WAN") { 15 }
            else if r.contains("firewall") { 10 }
            else { 5 };
        out.push(format!("!     +{:<3} {}", pts, r));
    }
    out.push("! ─────────────────────────────────────────────────────────────────────".to_string());
    out.push(String::new());
}

fn render_migration_complexity(cfg: &NetworkConfig, cls: &[(&Interface, ZoneClassification)], out: &mut Vec<String>) {
    let has_vlans   = !cfg.vlans.is_empty();
    let has_stp     = cfg.stp.is_some();
    let has_l2      = cfg.interfaces.iter().any(|i| i.l2.is_some());
    let unknown_ct  = cls.iter().filter(|(_, z)| z.zone == ZoneName::Unknown).count();

    let complexity = if has_vlans && has_stp { "HIGH" } else if has_l2 || unknown_ct > 10 { "MEDIUM" } else { "LOW" };

    out.push("! ── MIGRATION COMPLEXITY ─────────────────────────────────────────────".to_string());
    out.push(format!("!   Complexity: {}", complexity));
    out.push("!   Estimated effort:".to_string());
    if has_vlans {
        out.push(format!("!     VLAN redesign:          REQUIRED ({} VLANs to re-segment)", cfg.vlans.len()));
    }
    if has_stp {
        out.push("!     Loop prevention:        REQUIRED (deploy Eltex MES)".to_string());
    }
    if unknown_ct > 0 {
        out.push(format!("!     Zone classification:    REQUIRED ({} interfaces)", unknown_ct));
    }
    out.push("!     Firewall policy:         FROM SCRATCH (no source firewall)".to_string());
    out.push("!     Topology validation:     REQUIRED (test all traffic paths)".to_string());
    out.push("!".to_string());
    out.push("!   SAFE TARGET ARCHITECTURE:".to_string());
    out.push("!     [Hosts]──[Eltex MES L2 switch]──trunk──[ESR L3 gateway+FW]──[WAN]".to_string());
    out.push("!     MES handles: VLAN segmentation, STP, storm-control, voice VLAN".to_string());
    out.push("!     ESR handles: inter-VLAN routing, firewall, NAT, WAN".to_string());
    out.push("! ─────────────────────────────────────────────────────────────────────".to_string());
    out.push(String::new());
}

fn render_top_risks(cfg: &NetworkConfig, med_wan_ct: usize, out: &mut Vec<String>) {
    out.push("! ── TOP RISKS ────────────────────────────────────────────────────────".to_string());
    let mut n = 1;
    if cfg.stp.is_some() {
        out.push(format!("!   {}. [CRITICAL] STP removal — no L2 loop prevention", n));
        out.push("!      BLAST RADIUS: entire L2 domain".to_string());
        out.push("!      SCENARIO: one cable loop → broadcast storm → CPU spike → outage in seconds".to_string());
        n += 1;
    }
    if !cfg.vlans.is_empty() {
        out.push(format!("!   {}. [HIGH] VLAN collapse — loss of network segmentation", n));
        out.push(format!("!      BLAST RADIUS: entire network ({} VLANs merged)", cfg.vlans.len()));
        out.push("!      SCENARIO: security cameras, printers, workstations share L2 — lateral movement risk".to_string());
        n += 1;
    }
    if med_wan_ct > 0 {
        out.push(format!("!   {}. [MEDIUM] uncertain WAN classification", n));
        out.push("!      BLAST RADIUS: management plane".to_string());
        out.push("!      SCENARIO: mgmt interface in WAN zone → admin access exposed externally".to_string());
        n += 1;
    }
    out.push(format!("!   {}. [MEDIUM] incomplete firewall policy", n));
    out.push("!      BLAST RADIUS: network perimeter".to_string());
    out.push("!      SCENARIO: bootstrap permit-all applied → unrestricted outbound traffic".to_string());
    out.push("! ─────────────────────────────────────────────────────────────────────".to_string());
    out.push(String::new());
}

fn render_confidence_by_area(cls: &[(&Interface, ZoneClassification)], cfg: &NetworkConfig, out: &mut Vec<String>) {
    let high_ct  = cls.iter().filter(|(_, z)| z.confidence == ConfidenceLevel::High).count();
    let med_ct   = cls.iter().filter(|(_, z)| z.confidence == ConfidenceLevel::Medium).count();
    let low_ct   = cls.iter().filter(|(_, z)| z.confidence == ConfidenceLevel::Low).count();
    let wan_high = cls.iter().filter(|(_, z)| z.zone == ZoneName::Wan && z.confidence == ConfidenceLevel::High).count();
    let wan_med  = cls.iter().filter(|(_, z)| z.zone == ZoneName::Wan && z.confidence == ConfidenceLevel::Medium).count();

    out.push("! ── CONFIDENCE BY AREA ───────────────────────────────────────────────".to_string());
    out.push(format!("!   Interface roles:     {} high / {} medium / {} unknown",  high_ct, med_ct, low_ct));
    out.push(format!("!   WAN detection:       {} high, {} medium", wan_high, wan_med));
    out.push(format!("!   VLAN reconstruction: {}", if cfg.vlans.is_empty() { "N/A" } else { "HIGH (names preserved)" }));
    out.push("!   Firewall policy:     LOW (auto-generated bootstrap)".to_string());
    out.push(format!("!   Topology inference:  {}", if low_ct > 5 { "LOW (many unclassified ports)" } else { "MEDIUM" }));
    out.push("! ─────────────────────────────────────────────────────────────────────".to_string());
    out.push(String::new());
}

fn render_inference_table(
    cls: &[(&Interface, ZoneClassification)],
    unknown_ct: usize, access_ct: usize, trunk_ct: usize,
    out: &mut Vec<String>,
) {
    out.push("! ── INTERFACE ROLE INFERENCE ─────────────────────────────────────────".to_string());
    if unknown_ct > 0 {
        out.push(format!("! {} interfaces require manual zone assignment:", unknown_ct));
        if access_ct > 0 { out.push(format!("!   {} access ports → likely LAN endpoints (verify VLAN policy)", access_ct)); }
        if trunk_ct  > 0 { out.push(format!("!   {} trunk ports  → upstream router=WAN, downstream switch=LAN", trunk_ct)); }
        out.push("!".to_string());
    }
    for (iface, z) in cls {
        let icon = match z.confidence { ConfidenceLevel::High=>"✓ HIGH  ", ConfidenceLevel::Medium=>"~ MED   ", ConfidenceLevel::Low=>"? UNKNWN" };
        let vlan  = z.role.access_vlan().map(|v| format!(" VLAN {}", v)).unwrap_or_default();
        let zone  = match z.zone { ZoneName::Wan=>"WAN", ZoneName::Lan=>"LAN", ZoneName::Unknown=>"(unset)" };
        out.push(format!("! [{}] {:28} → {:10} role: {}{}", icon, iface.name.original, zone, z.role.label(), vlan));
        if z.zone == ZoneName::Wan && z.confidence == ConfidenceLevel::Medium {
            out.push(format!("!           ⚠ RISK: may be management — BLAST RADIUS: exposes admin plane"));
        }
    }
    out.push("! ─────────────────────────────────────────────────────────────────────".to_string());
    out.push(String::new());
}

fn render_config_validity_status(
    cfg: &NetworkConfig,
    cls: &[(&Interface, ZoneClassification)],
    unknown_ct: usize,
    out: &mut Vec<String>,
) {
    let user_ct      = cfg.users.iter().filter(|u| u.name != "enable").count();
    let snmp_conflict = cfg.snmp.as_ref().map(|s| s.communities.iter()
        .filter(|c| ["read","write","trap","all"].contains(&c.name.to_lowercase().as_str())).count())
        .unwrap_or(0);
    let med_wan = cls.iter().filter(|(_, z)| z.zone == ZoneName::Wan && z.confidence == ConfidenceLevel::Medium).count();

    let is_ready = unknown_ct == 0 && user_ct == 0 && snmp_conflict == 0 && med_wan == 0;

    out.push("! ── CONFIG STATUS ────────────────────────────────────────────────────".to_string());
    out.push(format!("!   Status: {}", if is_ready { "READY (review recommended)" } else { "NOT READY — do not apply" }));
    if !is_ready {
        out.push("!   Blocking issues:".to_string());
        if unknown_ct > 0 {
            out.push(format!("!     ✗ {} interfaces have no zone assignment", unknown_ct));
        }
        if user_ct > 0 {
            out.push(format!("!     ✗ {} user passwords not set", user_ct));
        }
        if snmp_conflict > 0 {
            out.push("!     ✗ SNMP community name conflicts with reserved keyword".to_string());
        }
        if med_wan > 0 {
            out.push(format!("!     ✗ {} WAN zone assignments unverified (medium confidence)", med_wan));
        }
        out.push("!   → Complete ACTION PLAN (Section 3) before applying".to_string());
    }
    out.push("! ─────────────────────────────────────────────────────────────────────".to_string());
    out.push(String::new());
}

fn render_manual_actions_summary(cfg: &NetworkConfig, cls: &[(&Interface, ZoneClassification)], out: &mut Vec<String>) {
    let unknown_ct   = cls.iter().filter(|(_, z)| z.zone == ZoneName::Unknown).count();
    let user_ct      = cfg.users.iter().filter(|u| u.name != "enable").count();
    let snmp_conflict = cfg.snmp.as_ref().map(|s| s.communities.iter()
        .filter(|c| ["read","write","trap","all"].contains(&c.name.to_lowercase().as_str())).count())
        .unwrap_or(0);
    let has_aaa    = cfg.aaa.as_ref().map(|a| a.new_model).unwrap_or(false);
    let has_enable = cfg.users.iter().any(|u| u.name == "enable");
    let med_wan    = cls.iter().filter(|(_, z)| z.zone == ZoneName::Wan && z.confidence == ConfidenceLevel::Medium).count();

    out.push("! QUICK SAFE MIGRATION PATH:".to_string());
    out.push("!   Step 1: DO NOT apply this config to production directly".to_string());
    out.push("!   Step 2: Deploy Eltex MES (L2 switch) — keep VLANs on MES".to_string());
    out.push("!   Step 3: Configure ESR as L3 gateway + firewall only".to_string());
    out.push("!   Step 4: Re-run netconv on L3-only router config (higher coverage)".to_string());
    out.push("!".to_string());
    out.push("! REQUIRED BEFORE APPLYING:".to_string());
    let mut step = 1;
    if unknown_ct > 0 {
        out.push(format!("!   {}. Assign security zones to {} interfaces (see INFERENCE above)", step, unknown_ct));
        out.push("!      Then uncomment the '! security-zone ???' lines in interface blocks".to_string());
        step += 1;
    }
    if user_ct > 0 {
        let names: Vec<_> = cfg.users.iter().filter(|u| u.name != "enable").map(|u| u.name.as_str()).collect();
        out.push(format!("!   {}. Set passwords for: {} (replace <NEW-PASSWORD> placeholders)", step, names.join(", ")));
        step += 1;
    }
    if has_enable {
        out.push(format!("!   {}. Configure privileged access (replaces 'enable secret')", step));
        step += 1;
    }
    if snmp_conflict > 0 {
        out.push(format!("!   {}. Rename SNMP community — 'write' conflicts with ESR keyword", step));
        step += 1;
    }
    if med_wan > 0 {
        out.push(format!("!   {}. Verify WAN interface classification ({} uncertain)", step, med_wan));
        step += 1;
    }
    if has_aaa {
        out.push(format!("!   {}. Configure AAA authentication scheme manually", step));
        step += 1;
    }
    out.push(format!("!   {}. Replace bootstrap firewall rules with site-specific policy", step));
    out.push(String::new());
}

fn render_firewall_safe_mode(cfg: &NetworkConfig, out: &mut Vec<String>, report: &mut ConversionReport) {
    out.push("! ── FIREWALL POLICY ──────────────────────────────────────────────────".to_string());
    out.push("! Default mode: SAFE (no rules generated — define policy manually)".to_string());
    out.push("!".to_string());
    out.push("! To enable bootstrap rules for initial connectivity test,".to_string());
    out.push("! uncomment the zone-pair blocks below.".to_string());

    // VLAN-based policy hints
    if !cfg.vlans.is_empty() {
        out.push("!".to_string());
        out.push("! SUGGESTED POLICY (implement after MES+ESR migration):".to_string());
        for vlan in &cfg.vlans {
            if let Some(name) = &vlan.name {
                let nl = name.to_lowercase();
                let policy = if nl.contains("camera") || nl.contains("security") || nl.contains("cctv") {
                    "deny internet, allow NVR/VMS only"
                } else if nl.contains("printer") || nl.contains("print") {
                    "allow from user VLANs only, deny internet"
                } else if nl.contains("voice") || nl.contains("voip") {
                    "allow SIP/RTP, mark DSCP EF, deny other internet"
                } else if nl.contains("guest") {
                    "allow internet only, deny all internal"
                } else if nl.contains("mgmt") || nl.contains("management") {
                    "allow from admin hosts only"
                } else {
                    "allow outbound, deny unsolicited inbound"
                };
                out.push(format!("!   VLAN {:>4}  {:20} → {}", vlan.id, name, policy));
            }
        }
    }

    out.push("!".to_string());
    out.push("! ── Bootstrap rules (COMMENTED OUT — uncomment only for testing) ──".to_string());
    for line in &[
        "! security zone-pair LAN WAN",
        "!  rule 10  ! permit all outbound — TESTING ONLY",
        "!   action permit",
        "!   enable",
        "!   exit",
        "!  exit",
        "! security zone-pair WAN self",
        "!  rule 10  ! permit SSH",
        "!   action permit",
        "!   match protocol tcp",
        "!   match destination-port 22",
        "!   enable",
        "!   exit",
        "!  rule 20  ! permit ICMP",
        "!   action permit",
        "!   match protocol icmp",
        "!   enable",
        "!   exit",
        "!  exit",
        "! security zone-pair LAN self",
        "!  rule 10  ! permit all from LAN — TESTING ONLY",
        "!   action permit",
        "!   enable",
        "!   exit",
        "!  exit",
    ] { out.push(line.to_string()); }

    out.push("! ─────────────────────────────────────────────────────────────────────".to_string());
    out.push(String::new());

    report.add_manual("firewall",
        "# (no firewall in source config)",
        "SAFE MODE: no firewall rules generated. Define policy manually.",
        Some("Uncomment bootstrap blocks for initial test, then replace with production rules."));
}

fn render_architecture_summary(
    cfg: &NetworkConfig,
    cls: &[(&Interface, ZoneClassification)],
    risk: &netconv_core::report::RiskScore,
    out: &mut Vec<String>,
) {
    let has_vlans = !cfg.vlans.is_empty();
    let has_l2    = cfg.interfaces.iter().any(|i| i.l2.is_some());
    let has_stp   = cfg.stp.is_some();
    let trunk_ct  = cls.iter().filter(|(_, z)| z.role == InterfaceRole::TrunkInterswitch).count();
    let access_ct = cls.iter().filter(|(_, z)| matches!(z.role, InterfaceRole::AccessEndpoint { .. })).count();

    out.push("! ── ARCHITECTURE CHANGE ANALYSIS ─────────────────────────────────────".to_string());
    if has_l2 || has_vlans {
        out.push("!   SOURCE:  L2 managed switch".to_string());
        if has_vlans {
            out.push(format!("!     VLANs: {}", cfg.vlans.iter()
                .map(|v| format!("{}{}", v.id, v.name.as_ref().map(|n| format!("({})",n)).unwrap_or_default()))
                .collect::<Vec<_>>().join(", ")));
        }
        if trunk_ct + access_ct > 0 {
            out.push(format!("!     Ports: {} trunk uplinks, {} access endpoints", trunk_ct, access_ct));
        }
        if has_stp { out.push("!     Loop:  STP rapid-pvst active".to_string()); }
    } else {
        out.push("!   SOURCE:  L3 router".to_string());
    }
    out.push("!   TARGET:  Eltex ESR — L3 router + stateful zone-based firewall".to_string());
    out.push("!   L2 support: NONE — segmentation model changes fundamentally".to_string());
    out.push(format!("!   RISK LEVEL: {}", risk.level.label()));
    out.push("! ─────────────────────────────────────────────────────────────────────".to_string());
    out.push(String::new());
}

fn compute_risk_score(
    cfg: &NetworkConfig,
    cls: &[(&Interface, ZoneClassification)],
    report: &mut ConversionReport,
) {
    let mut reasons: Vec<String> = vec![];
    let mut recommendations: Vec<String> = vec![];
    let mut score: u32 = 0;

    if cfg.interfaces.iter().any(|i| i.l2.is_some()) || !cfg.vlans.is_empty() {
        score += 40;
        reasons.push(format!("device class mismatch: L2 switch → L3 router ({} VLANs)", cfg.vlans.len()));
        recommendations.push("Use Eltex MES for L2, ESR as L3 gateway only".to_string());
    }
    if !cfg.vlans.is_empty() {
        score += 20;
        reasons.push(format!("{} VLANs → single broadcast domain", cfg.vlans.len()));
        recommendations.push("Security isolation and performance impact".to_string());
    }
    if cfg.stp.is_some() {
        score += 15;
        reasons.push("STP removed — broadcast storm risk".to_string());
        recommendations.push("Ensure upstream switch handles loop prevention".to_string());
    }
    score += 10;
    reasons.push("firewall auto-generated (no source firewall)".to_string());
    recommendations.push("Define production firewall policy from scratch".to_string());
    let unknown_ct = cls.iter().filter(|(_, z)| z.zone == ZoneName::Unknown).count();
    if unknown_ct > 0 {
        score += (unknown_ct as u32).min(10);
        reasons.push(format!("{} interfaces require manual zone assignment", unknown_ct));
        recommendations.push("Classify all interfaces before applying".to_string());
    }
    let med_wan = cls.iter().filter(|(_, z)| z.zone == ZoneName::Wan && z.confidence == ConfidenceLevel::Medium).count();
    if med_wan > 0 {
        score += 15;
        reasons.push(format!("{} uncertain WAN classification(s)", med_wan));
        recommendations.push("Verify medium-confidence WAN interfaces".to_string());
    }
    let level = match score { 0..=20=>RiskLevel::Low, 21..=40=>RiskLevel::Medium, 41..=70=>RiskLevel::High, _=>RiskLevel::Critical };
    report.risk = netconv_core::report::RiskScore { level, reasons, recommendations };
}

pub fn render_risk_score_comment(risk: &netconv_core::report::RiskScore, out: &mut Vec<String>) {
    out.push("! ══════════════════════════════════════════════════════════════════".to_string());
    out.push(format!("! FINAL RISK SCORE: {}", risk.level.label()));
    for r in &risk.reasons { out.push(format!("!   - {}", r)); }
    out.push("! ══════════════════════════════════════════════════════════════════".to_string());
    out.push(String::new());
}
