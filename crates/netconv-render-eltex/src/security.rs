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
        match self { ZoneName::Wan => "WAN", ZoneName::Lan => "LAN", ZoneName::Unknown => "UNASSIGNED" }
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
            InterfaceRole::WanUplink                         => "WAN uplink",
            InterfaceRole::ManagementSuspected               => "management (suspected)",
            InterfaceRole::AccessEndpoint { .. }             => "access endpoint",
            InterfaceRole::TrunkInterswitch                  => "trunk/inter-switch",
            InterfaceRole::Loopback                          => "loopback",
            InterfaceRole::Unknown                           => "unclassified",
        }
    }
    pub fn access_vlan(&self) -> Option<u16> {
        if let InterfaceRole::AccessEndpoint { vlan } = self { *vlan } else { None }
    }
}

pub fn classify_zone(iface: &Interface, cfg: &NetworkConfig) -> ZoneClassification {
    // HIGH: NAT outside
    if iface.nat_direction == Some(NatDirection::Outside) {
        return ZoneClassification { zone: ZoneName::Wan, confidence: ConfidenceLevel::High,
            reason: "nat outside configured".to_string(), role: InterfaceRole::WanUplink };
    }
    // HIGH: description keyword
    if let Some(desc) = &iface.description {
        let d = desc.to_lowercase();
        for kw in &["uplink","wan","isp","internet","external","provider","upstream","transit","peering"] {
            if d.contains(kw) {
                return ZoneClassification { zone: ZoneName::Wan, confidence: ConfidenceLevel::High,
                    reason: format!("description contains '{}'", kw), role: InterfaceRole::WanUplink };
            }
        }
    }
    // MEDIUM: default route path
    for route in &cfg.routing.static_routes {
        if route.prefix.to_string() == "0.0.0.0/0" {
            if let Some(addr) = iface.addresses.first() {
                if let NextHop::Ip(nh) = &route.next_hop {
                    if addr.prefix.contains(nh) {
                        let is_vlan1 = matches!(&iface.name.kind, InterfaceKind::Vlan) && iface.name.id == "1";
                        return ZoneClassification {
                            zone: ZoneName::Wan, confidence: ConfidenceLevel::Medium,
                            reason: if is_vlan1 { "default route via VLAN1 — likely management, NOT WAN".to_string() }
                                    else { "default route next-hop reachable via this interface".to_string() },
                            role: if is_vlan1 { InterfaceRole::ManagementSuspected } else { InterfaceRole::WanUplink },
                        };
                    }
                }
            }
        }
    }
    // Loopback → LAN HIGH
    if iface.name.kind == InterfaceKind::Loopback {
        return ZoneClassification { zone: ZoneName::Lan, confidence: ConfidenceLevel::High,
            reason: "loopback interface".to_string(), role: InterfaceRole::Loopback };
    }
    // L2 ports → UNKNOWN (честно)
    if let Some(l2) = &iface.l2 {
        return match l2.mode {
            L2Mode::Trunk => ZoneClassification { zone: ZoneName::Unknown, confidence: ConfidenceLevel::Low,
                reason: "trunk port — inter-switch link, cannot determine zone automatically".to_string(),
                role: InterfaceRole::TrunkInterswitch },
            L2Mode::Access => ZoneClassification { zone: ZoneName::Unknown, confidence: ConfidenceLevel::Low,
                reason: format!("access port{} — endpoint classification ambiguous",
                    l2.access_vlan.map(|v| format!(" VLAN {}", v)).unwrap_or_default()),
                role: InterfaceRole::AccessEndpoint { vlan: l2.access_vlan } },
        };
    }
    // IP-only interface without signals → UNKNOWN
    ZoneClassification { zone: ZoneName::Unknown, confidence: ConfidenceLevel::Low,
        reason: "no classification signals — manual assignment required".to_string(),
        role: InterfaceRole::Unknown }
}

pub fn render_security_zones(cfg: &NetworkConfig, out: &mut Vec<String>, report: &mut ConversionReport) {
    let cls: Vec<(&Interface, ZoneClassification)> = cfg.interfaces.iter()
        .map(|i| (i, classify_zone(i, cfg))).collect();

    let has_wan      = cls.iter().any(|(_, z)| z.zone == ZoneName::Wan);
    let unknown_ct   = cls.iter().filter(|(_, z)| z.zone == ZoneName::Unknown).count();
    let access_ct    = cls.iter().filter(|(_, z)| matches!(z.role, InterfaceRole::AccessEndpoint { .. })).count();
    let trunk_ct     = cls.iter().filter(|(_, z)| z.role == InterfaceRole::TrunkInterswitch).count();
    let med_wan_ct   = cls.iter().filter(|(_, z)| z.zone == ZoneName::Wan && z.confidence == ConfidenceLevel::Medium).count();

    compute_risk_score(cfg, &cls, report);
    let risk_snapshot = report.risk.clone();

    // 1. ARCHITECTURE CHANGE ANALYSIS + QUICK PATH
    render_architecture_summary(cfg, &cls, &risk_snapshot, out);

    // 2. Zone declarations — только те что ИЗВЕСТНЫ
    out.push("! Security zones (only classified zones declared)".to_string());
    out.push("security zone LAN".to_string());
    out.push(" exit".to_string());
    if has_wan {
        out.push("security zone WAN".to_string());
        out.push(" exit".to_string());
    }
    if unknown_ct > 0 {
        out.push(format!("! {} zones NOT declared — requires manual classification before use", unknown_ct));
    }
    out.push(String::new());

    // 3. CONFIDENCE BY AREA
    render_confidence_by_area(&cls, cfg, out);

    // 4. TOP RISKS
    render_top_risks(cfg, &cls, med_wan_ct, out);

    // 5. INTERFACE ROLE INFERENCE
    out.push("! ── INTERFACE ROLE INFERENCE ────────────────────────────────────────".to_string());
    if unknown_ct > 0 {
        out.push(format!("! {} interfaces — zone UNASSIGNED:", unknown_ct));
        if access_ct > 0 { out.push(format!("!   {} access ports → likely LAN, but verify VLAN policy first", access_ct)); }
        if trunk_ct > 0  { out.push(format!("!   {} trunk ports  → upstream router=WAN, downstream switch=LAN", trunk_ct)); }
        out.push("!".to_string());
    }
    for (iface, z) in &cls {
        let icon = match z.confidence { ConfidenceLevel::High=>"✓ HIGH  ", ConfidenceLevel::Medium=>"~ MED   ", ConfidenceLevel::Low=>"? UNKNWN" };
        let vlan_sfx = z.role.access_vlan().map(|v| format!(" VLAN {}", v)).unwrap_or_default();
        out.push(format!("! [{}] {:28} → {:10}  role: {}{}", icon, iface.name.original, z.zone.as_str(), z.role.label(), vlan_sfx));
        if z.zone == ZoneName::Wan && z.confidence == ConfidenceLevel::Medium {
            out.push(format!("!           ⚠ RISK: {} — may be management, NOT WAN", iface.name.original));
            out.push(format!("!           BLAST RADIUS: misclassification exposes management plane externally"));
        }
    }
    out.push("! ─────────────────────────────────────────────────────────────────────".to_string());
    out.push(String::new());

    // 6. MANUAL ACTIONS SUMMARY (агрегированно)
    render_manual_actions_summary(cfg, &cls, out);

    // 7. Firewall
    if has_wan { render_basic_firewall(cfg, out, report); }

    // 8. Report — минимальный, без дублирования inference
    // Одна запись для всех unknown
    if unknown_ct > 0 {
        report.add_manual("security_zones",
            &format!("{} interfaces unassigned", unknown_ct),
            &format!("{} interfaces require manual zone assignment (see INTERFACE ROLE INFERENCE in config)", unknown_ct),
            Some("Assign access ports → LAN, verify trunk ports, then re-run"));
    }
    // WAN с высоким confidence → approve
    for (iface, z) in cls.iter().filter(|(_, z)| z.zone == ZoneName::Wan && z.confidence == ConfidenceLevel::High) {
        report.add_approximate("security_zone.wan",
            &format!("interface {}", iface.name.original), "WAN",
            &format!("WAN [HIGH]: {}", z.reason));
    }
    // WAN с medium → manual
    for (iface, z) in cls.iter().filter(|(_, z)| z.zone == ZoneName::Wan && z.confidence == ConfidenceLevel::Medium) {
        report.add_manual("security_zone.wan.uncertain",
            &format!("interface {}", iface.name.original),
            &format!("WAN [MEDIUM confidence]: {} — verify topology", z.reason),
            Some("May be management interface — confirm before applying"));
    }
}

fn render_confidence_by_area(cls: &[(&Interface, ZoneClassification)], cfg: &NetworkConfig, out: &mut Vec<String>) {
    let high_ct   = cls.iter().filter(|(_, z)| z.confidence == ConfidenceLevel::High).count();
    let med_ct    = cls.iter().filter(|(_, z)| z.confidence == ConfidenceLevel::Medium).count();
    let low_ct    = cls.iter().filter(|(_, z)| z.confidence == ConfidenceLevel::Low).count();
    let wan_high  = cls.iter().filter(|(_, z)| z.zone == ZoneName::Wan && z.confidence == ConfidenceLevel::High).count();
    let wan_med   = cls.iter().filter(|(_, z)| z.zone == ZoneName::Wan && z.confidence == ConfidenceLevel::Medium).count();

    out.push("! ── CONFIDENCE BY AREA ───────────────────────────────────────────────".to_string());
    out.push(format!("!   Interface roles:     {} high / {} medium / {} unknown",  high_ct, med_ct, low_ct));
    out.push(format!("!   WAN detection:       {} high, {} medium confidence",     wan_high, wan_med));
    out.push(format!("!   VLAN reconstruction: {} (names preserved from source)",  if cfg.vlans.is_empty() { "N/A" } else { "HIGH" }));
    out.push(format!("!   Firewall policy:     LOW (auto-generated bootstrap)"));
    out.push(format!("!   Topology inference:  {} (based on port types only)", if low_ct > 0 { "LOW" } else { "MEDIUM" }));
    out.push("! ─────────────────────────────────────────────────────────────────────".to_string());
    out.push(String::new());
}

fn render_top_risks(
    cfg: &NetworkConfig,
    _cls: &[(&Interface, ZoneClassification)],
    med_wan_ct: usize,
    out: &mut Vec<String>,
) {
    let mut risks: Vec<(&str, &str, &str)> = vec![]; // (severity, risk, blast_radius)

    if cfg.stp.is_some() {
        risks.push(("CRITICAL", "STP removal — no L2 loop prevention",
            "entire L2 domain — one cable loop causes broadcast storm → network outage"));
    }
    if !cfg.vlans.is_empty() {
        risks.push(("HIGH", "VLAN collapse — loss of network segmentation",
            "entire network — all hosts in one broadcast domain, security isolation gone"));
    }
    if med_wan_ct > 0 {
        risks.push(("MEDIUM", "uncertain WAN classification — may expose management interface",
            "management plane — wrong zone puts admin access on external-facing zone"));
    }
    risks.push(("MEDIUM", "bootstrap firewall policy — overly permissive rules",
        "network perimeter — all outbound permitted, insufficient for production"));

    if risks.is_empty() { return; }

    out.push("! ── TOP RISKS ───────────────────────────────────────────────────────".to_string());
    for (i, (severity, risk, blast)) in risks.iter().enumerate() {
        out.push(format!("! {}. [{}] {}", i + 1, severity, risk));
        out.push(format!("!    BLAST RADIUS: {}", blast));
    }
    out.push("! ─────────────────────────────────────────────────────────────────────".to_string());
    out.push(String::new());
}

fn render_manual_actions_summary(cfg: &NetworkConfig, cls: &[(&Interface, ZoneClassification)], out: &mut Vec<String>) {
    let unknown_ct    = cls.iter().filter(|(_, z)| z.zone == ZoneName::Unknown).count();
    let user_ct       = cfg.users.iter().filter(|u| u.name != "enable").count();
    let snmp_conflict = cfg.snmp.as_ref().map(|s| s.communities.iter()
        .filter(|c| ["read","write","trap","all"].contains(&c.name.to_lowercase().as_str())).count())
        .unwrap_or(0);
    let has_aaa = cfg.aaa.as_ref().map(|a| a.new_model).unwrap_or(false);
    let has_enable = cfg.users.iter().any(|u| u.name == "enable");

    let total = (if unknown_ct > 0 {1} else {0}) + (if user_ct > 0 {1} else {0})
        + snmp_conflict + (if has_aaa {1} else {0}) + (if has_enable {1} else {0});
    if total == 0 { return; }

    out.push("! ── MANUAL ACTIONS REQUIRED ─────────────────────────────────────────".to_string());
    if unknown_ct > 0 {
        out.push(format!("!   1. Assign security zones to {} interfaces (see INFERENCE above)", unknown_ct));
    }
    if user_ct > 0 {
        let names: Vec<_> = cfg.users.iter().filter(|u| u.name != "enable").map(|u| u.name.as_str()).collect();
        out.push(format!("!   2. Set passwords for: {}", names.join(", ")));
    }
    if has_enable {
        out.push("!   3. Configure privileged access (replaces 'enable secret')".to_string());
    }
    if snmp_conflict > 0 {
        out.push("!   4. Rename SNMP community 'write' — conflicts with VRP keyword".to_string());
    }
    if has_aaa {
        out.push("!   5. Configure AAA authentication scheme".to_string());
    }
    out.push("!   → Apply QUICK SAFE MIGRATION PATH (see top of file)".to_string());
    out.push("! ─────────────────────────────────────────────────────────────────────".to_string());
    out.push(String::new());
}

fn render_basic_firewall(cfg: &NetworkConfig, out: &mut Vec<String>, report: &mut ConversionReport) {
    out.push("! ── FIREWALL RULES ──────────────────────────────────────────────────".to_string());
    out.push("! ⚠ LOW CONFIDENCE: Generic bootstrap rules — NOT a production policy.".to_string());
    out.push("!   Option A (current): permissive — initial connectivity test only.".to_string());
    out.push("!   Option B: deny-by-default + explicit allow rules (recommended).".to_string());

    if !cfg.vlans.is_empty() {
        out.push("!".to_string());
        out.push("! SUGGESTED POLICY (based on detected VLANs — implement after migration):".to_string());
        for vlan in &cfg.vlans {
            if let Some(name) = &vlan.name {
                let nl = name.to_lowercase();
                let policy = if nl.contains("camera") || nl.contains("security") || nl.contains("cctv") {
                    "deny internet, allow NVR/VMS hosts only"
                } else if nl.contains("printer") || nl.contains("print") {
                    "allow from user VLANs only, deny internet"
                } else if nl.contains("voice") || nl.contains("voip") || nl.contains("phone") {
                    "allow SIP/RTP, mark DSCP EF, deny other internet"
                } else if nl.contains("guest") {
                    "allow internet only, deny all internal segments"
                } else if nl.contains("mgmt") || nl.contains("management") {
                    "allow from admin hosts only, deny all else"
                } else {
                    "allow outbound, deny unsolicited inbound"
                };
                out.push(format!("!   VLAN {:>4}  {:20} → {}", vlan.id, name, policy));
            }
        }
    }
    out.push("! ─────────────────────────────────────────────────────────────────────".to_string());

    out.push("security zone-pair LAN WAN".to_string());
    out.push(" rule 10  ! ⚠ BOOTSTRAP ONLY".to_string());
    out.push("  action permit".to_string());
    out.push("  enable".to_string());
    out.push("  exit".to_string());
    out.push(" exit".to_string());

    out.push("security zone-pair WAN self".to_string());
    out.push(" rule 10  ! SSH management access".to_string());
    out.push("  action permit".to_string());
    out.push("  match protocol tcp".to_string());
    out.push("  match destination-port 22".to_string());
    out.push("  enable".to_string());
    out.push("  exit".to_string());
    out.push(" rule 20  ! ICMP for diagnostics".to_string());
    out.push("  action permit".to_string());
    out.push("  match protocol icmp".to_string());
    out.push("  enable".to_string());
    out.push("  exit".to_string());
    out.push(" exit".to_string());

    out.push("security zone-pair LAN self".to_string());
    out.push(" rule 10  ! ⚠ BOOTSTRAP ONLY".to_string());
    out.push("  action permit".to_string());
    out.push("  enable".to_string());
    out.push("  exit".to_string());
    out.push(" exit".to_string());
    out.push(String::new());

    report.add_manual("firewall.bootstrap", "# (no firewall in source config)",
        "LOW CONFIDENCE: Bootstrap rules. NOT production policy.",
        Some("Replace with deny-by-default + explicit allow before deploying."));
}

fn render_architecture_summary(
    cfg: &NetworkConfig,
    cls: &[(&Interface, ZoneClassification)],
    risk: &netconv_core::report::RiskScore,
    out: &mut Vec<String>,
) {
    let has_vlans  = !cfg.vlans.is_empty();
    let has_l2     = cfg.interfaces.iter().any(|i| i.l2.is_some());
    let has_stp    = cfg.stp.is_some();
    let trunk_ct   = cls.iter().filter(|(_, z)| z.role == InterfaceRole::TrunkInterswitch).count();
    let access_ct  = cls.iter().filter(|(_, z)| matches!(z.role, InterfaceRole::AccessEndpoint { .. })).count();

    out.push("! ══════════════════════════════════════════════════════════════════".to_string());
    out.push("! ARCHITECTURE CHANGE ANALYSIS".to_string());
    out.push("! ══════════════════════════════════════════════════════════════════".to_string());
    out.push("!".to_string());

    if has_l2 || has_vlans {
        out.push("! SOURCE:  L2 managed switch".to_string());
        if has_vlans {
            out.push(format!("!   VLANs: {} ({} named)", cfg.vlans.len(),
                cfg.vlans.iter().filter(|v| v.name.is_some()).count()));
            for v in &cfg.vlans {
                out.push(format!("!     {:>4}: {}", v.id, v.name.as_deref().unwrap_or("(unnamed)")));
            }
        }
        if trunk_ct + access_ct > 0 {
            out.push(format!("!   Topology: hierarchical ({} trunk uplinks, {} access ports)", trunk_ct, access_ct));
        }
        if has_stp { out.push("!   Loop protection: STP rapid-pvst".to_string()); }
    } else {
        out.push("! SOURCE:  L3 router".to_string());
    }

    out.push("!".to_string());
    out.push("! TARGET:  Eltex ESR — L3 router + stateful zone-based firewall".to_string());
    out.push("!   L2 switching: NOT SUPPORTED".to_string());
    out.push("!".to_string());

    if has_l2 || has_vlans {
        out.push("! WHAT CHANGES:".to_string());
        if has_vlans {
            out.push(format!("!   • {} VLANs → single broadcast domain", cfg.vlans.len()));
            out.push("!     IMPACT: security isolation lost, broadcast domain expands".to_string());
            if cfg.interfaces.iter().any(|i| i.voice_vlan.is_some()) {
                out.push("!     IMPACT: voice/data separation disappears → QoS degradation".to_string());
            }
        }
        if has_stp {
            out.push("!   • STP removed → no L2 loop protection".to_string());
            out.push("!     IMPACT: one cable loop = broadcast storm = network-wide outage".to_string());
        }
        if trunk_ct > 0 {
            out.push(format!("!   • {} trunk links → L3 only (no L2 pass-through)", trunk_ct));
            out.push("!     IMPACT: hierarchical L2 topology replaced by flat L3".to_string());
        }
        out.push("!".to_string());
        out.push(format!("! RISK LEVEL: {}", risk.level.label()));
        out.push("!".to_string());
        out.push("! ── QUICK SAFE MIGRATION PATH ──────────────────────────────────".to_string());
        out.push("! Step 1: DO NOT apply this config to production directly".to_string());
        out.push("! Step 2: Deploy Eltex MES (L2 managed switch)".to_string());
        out.push("!         Keep all VLAN segmentation on MES".to_string());
        out.push("!         MES uplink → ESR via trunk (all VLANs tagged)".to_string());
        out.push("! Step 3: Configure ESR as L3 gateway + firewall only".to_string());
        out.push("!         One subinterface per VLAN on ESR uplink port".to_string());
        out.push("!         Zone-pair rules between zones for firewall policy".to_string());
        out.push("! Step 4: Re-run netconv on ESR L3-only router config".to_string());
        out.push("!         Coverage and confidence will be significantly higher".to_string());
        out.push("! ────────────────────────────────────────────────────────────────".to_string());
    } else {
        out.push(format!("! RISK LEVEL: {}", risk.level.label()));
    }

    out.push("! ══════════════════════════════════════════════════════════════════".to_string());
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
        reasons.push(format!("{} VLANs → single broadcast domain (security isolation lost)", cfg.vlans.len()));
        recommendations.push("All hosts share one domain — security and performance impact".to_string());
    }
    if cfg.stp.is_some() {
        score += 15;
        reasons.push("STP removed — broadcast storm risk (no loop prevention)".to_string());
        recommendations.push("Ensure upstream switch handles loop prevention".to_string());
    }
    score += 10;
    reasons.push("firewall policy auto-generated (no source firewall to migrate)".to_string());
    recommendations.push("Harden zone-pair rules before production".to_string());

    let unknown_ct = cls.iter().filter(|(_, z)| z.zone == ZoneName::Unknown).count();
    if unknown_ct > 0 {
        score += (unknown_ct as u32).min(10);
        reasons.push(format!("{} interfaces require manual zone assignment", unknown_ct));
        recommendations.push("Classify all unresolved interfaces before applying".to_string());
    }
    let med_wan_ct = cls.iter().filter(|(_, z)| z.zone == ZoneName::Wan && z.confidence == ConfidenceLevel::Medium).count();
    if med_wan_ct > 0 {
        score += 15;
        reasons.push(format!("{} uncertain WAN classification(s) — may expose management plane", med_wan_ct));
        recommendations.push("Verify medium-confidence WAN interfaces".to_string());
    }

    let level = match score { 0..=20 => RiskLevel::Low, 21..=40 => RiskLevel::Medium, 41..=70 => RiskLevel::High, _ => RiskLevel::Critical };
    report.risk = netconv_core::report::RiskScore { level, reasons, recommendations };
}

pub fn render_risk_score_comment(risk: &netconv_core::report::RiskScore, out: &mut Vec<String>) {
    out.push("! ══════════════════════════════════════════════════════════════════".to_string());
    out.push(format!("! FINAL RISK SCORE: {}", risk.level.label()));
    if !risk.reasons.is_empty() {
        out.push("! Factors:".to_string());
        for r in &risk.reasons { out.push(format!("!   - {}", r)); }
    }
    if !risk.recommendations.is_empty() {
        out.push("! Required actions:".to_string());
        for r in &risk.recommendations { out.push(format!("!   → {}", r)); }
    }
    out.push("! ══════════════════════════════════════════════════════════════════".to_string());
    out.push(String::new());
}
