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
        match self { ZoneName::Wan => "WAN", _ => "LAN" }
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
            InterfaceRole::WanUplink                     => "WAN uplink",
            InterfaceRole::ManagementSuspected           => "management (suspected)",
            InterfaceRole::AccessEndpoint { vlan: None } => "access endpoint",
            InterfaceRole::AccessEndpoint { vlan: Some(_) } => "access endpoint",
            InterfaceRole::TrunkInterswitch              => "trunk/inter-switch",
            InterfaceRole::Loopback                      => "loopback",
            InterfaceRole::Unknown                       => "unclassified",
        }
    }
    pub fn access_vlan(&self) -> Option<u16> {
        if let InterfaceRole::AccessEndpoint { vlan } = self { *vlan } else { None }
    }
}

pub fn classify_zone(iface: &Interface, cfg: &NetworkConfig) -> ZoneClassification {
    if iface.nat_direction == Some(NatDirection::Outside) {
        return ZoneClassification { zone: ZoneName::Wan, confidence: ConfidenceLevel::High,
            reason: "nat outside".to_string(), role: InterfaceRole::WanUplink };
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
                            reason: if is_vlan1 { "default route via VLAN1 — likely management, NOT WAN".to_string() }
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
            reason: "loopback".to_string(), role: InterfaceRole::Loopback };
    }

    if let Some(l2) = &iface.l2 {
        return match l2.mode {
            L2Mode::Trunk => ZoneClassification { zone: ZoneName::Unknown, confidence: ConfidenceLevel::Low,
                reason: "trunk port — manual zone assignment required".to_string(),
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
    let unknown    = cls.iter().filter(|(_, z)| z.zone == ZoneName::Unknown).count();
    let access_ct  = cls.iter().filter(|(_, z)| matches!(z.role, InterfaceRole::AccessEndpoint { .. })).count();
    let trunk_ct   = cls.iter().filter(|(_, z)| z.role == InterfaceRole::TrunkInterswitch).count();

    compute_risk_score(cfg, &cls, report);

    // 1. ARCHITECTURE CHANGE ANALYSIS
    render_architecture_summary(cfg, &cls, &report.risk.clone(), out);

    // 2. Zone declarations
    out.push("security zone LAN".to_string());
    out.push(" exit".to_string());
    if has_wan {
        out.push("security zone WAN".to_string());
        out.push(" exit".to_string());
    }
    out.push(String::new());

    // 3. CONFIDENCE SUMMARY
    render_confidence_summary(&cls, out);

    // 4. INTERFACE ROLE INFERENCE (human-readable, no report duplication)
    out.push("! ── INTERFACE ROLE INFERENCE ────────────────────────────────────────".to_string());
    if unknown > 0 {
        out.push(format!("! {} interfaces require manual zone assignment:", unknown));
        if access_ct > 0 { out.push(format!("!   {} access ports → likely LAN endpoints (assign to LAN zone)", access_ct)); }
        if trunk_ct > 0  { out.push(format!("!   {} trunk ports  → verify: upstream router=WAN, downstream switch=LAN", trunk_ct)); }
        out.push("!".to_string());
    }
    for (iface, z) in &cls {
        let icon = match z.confidence { ConfidenceLevel::High=>"✓ HIGH  ", ConfidenceLevel::Medium=>"~ MED   ", ConfidenceLevel::Low=>"? UNKNWN" };
        let zone_str = match z.zone { ZoneName::Wan=>"WAN", ZoneName::Lan=>"LAN", ZoneName::Unknown=>"??? (assign manually)" };
        let vlan_suffix = z.role.access_vlan().map(|v| format!(" (VLAN {})", v)).unwrap_or_default();
        out.push(format!("! [{}] {:28} → {}  {}{}", icon, iface.name.original, zone_str, z.role.label(), vlan_suffix));
        if z.zone == ZoneName::Wan && z.confidence == ConfidenceLevel::Medium {
            out.push(format!("!           ⚠ RISK: may be management interface — {}", z.reason));
        }
    }
    out.push("! ─────────────────────────────────────────────────────────────────────".to_string());
    out.push(String::new());

    // 5. MANUAL ACTIONS SUMMARY (агрегированно, не 35 строк)
    render_manual_actions_summary(cfg, &cls, out);

    // 6. Firewall с policy hints
    if has_wan { render_basic_firewall(cfg, out, report); }

    // 7. Report — агрегированные записи вместо per-interface дублей
    // Одна запись для всех unknown zones
    if unknown > 0 {
        report.add_manual(
            "security_zone.unknown",
            &format!("{} interfaces", unknown),
            &format!("{} interfaces require manual zone assignment (see INTERFACE ROLE INFERENCE in config)", unknown),
            Some("Assign access ports to LAN, verify trunk ports before applying"),
        );
    }
    for (iface, z) in &cls {
        if z.zone == ZoneName::Wan {
            match z.confidence {
                ConfidenceLevel::High => {
                    report.add_approximate("security_zone.wan",
                        &format!("interface {}", iface.name.original), "WAN",
                        &format!("WAN [HIGH confidence]: {}", z.reason));
                }
                _ => {
                    report.add_manual("security_zone.wan.uncertain",
                        &format!("interface {}", iface.name.original),
                        &format!("WAN [MEDIUM confidence]: {} — verify before applying", z.reason),
                        Some("May be management interface — confirm topology"));
                }
            }
        }
    }
    report.add_approximate("security_zones", "# (Cisco IOS has no security zones)",
        if has_wan { "LAN + WAN zones" } else { "LAN zone" },
        "ESR requires security zones. See INTERFACE ROLE INFERENCE in generated config.");
}

fn render_confidence_summary(cls: &[(&Interface, ZoneClassification)], out: &mut Vec<String>) {
    let high_count   = cls.iter().filter(|(_, z)| z.confidence == ConfidenceLevel::High).count();
    let medium_count = cls.iter().filter(|(_, z)| z.confidence == ConfidenceLevel::Medium).count();
    let low_count    = cls.iter().filter(|(_, z)| z.confidence == ConfidenceLevel::Low).count();
    let total = cls.len();

    let overall = if low_count > total / 2 { "LOW" }
                  else if medium_count > 0 { "MEDIUM" }
                  else { "HIGH" };

    let wan_high  = cls.iter().filter(|(_, z)| z.zone == ZoneName::Wan && z.confidence == ConfidenceLevel::High).count();
    let wan_med   = cls.iter().filter(|(_, z)| z.zone == ZoneName::Wan && z.confidence == ConfidenceLevel::Medium).count();

    out.push("! ── CONFIDENCE SUMMARY ──────────────────────────────────────────────".to_string());
    out.push(format!("!   WAN detection:  {} high, {} medium confidence", wan_high, wan_med));
    out.push(format!("!   Classification: {} high / {} medium / {} require manual assignment", high_count, medium_count, low_count));
    out.push(format!("!   Overall:        {}", overall));
    if low_count > 0 {
        out.push(format!("!   ⚠ {} interfaces classified as UNKNOWN — manual review required", low_count));
    }
    out.push("! ─────────────────────────────────────────────────────────────────────".to_string());
    out.push(String::new());
}

fn render_manual_actions_summary(cfg: &NetworkConfig, cls: &[(&Interface, ZoneClassification)], out: &mut Vec<String>) {
    let unknown_ct = cls.iter().filter(|(_, z)| z.zone == ZoneName::Unknown).count();
    let user_ct    = cfg.users.iter().filter(|u| u.name != "enable").count();
    let snmp_reserved = cfg.snmp.as_ref().map(|s| s.communities.iter()
        .filter(|c| ["read","write","trap","all"].contains(&c.name.to_lowercase().as_str())).count())
        .unwrap_or(0);
    let has_aaa   = cfg.aaa.as_ref().map(|a| a.new_model).unwrap_or(false);

    let total_actions = (if unknown_ct > 0 { 1 } else { 0 })
        + (if user_ct > 0 { 1 } else { 0 })
        + snmp_reserved
        + (if has_aaa { 1 } else { 0 });

    if total_actions == 0 { return; }

    out.push("! ── MANUAL ACTIONS REQUIRED ─────────────────────────────────────────".to_string());
    if unknown_ct > 0 {
        out.push(format!("!   • {} interfaces: assign security zones (see INFERENCE above)", unknown_ct));
    }
    if user_ct > 0 {
        let names: Vec<_> = cfg.users.iter().filter(|u| u.name != "enable").map(|u| u.name.as_str()).collect();
        out.push(format!("!   • {} user passwords: set new passwords for: {}", user_ct, names.join(", ")));
    }
    if snmp_reserved > 0 {
        out.push("!   • SNMP: rename community with reserved name (e.g. 'write')".to_string());
    }
    if has_aaa {
        out.push("!   • AAA: configure authentication scheme manually".to_string());
    }
    out.push("! ─────────────────────────────────────────────────────────────────────".to_string());
    out.push(String::new());
}

fn render_basic_firewall(cfg: &NetworkConfig, out: &mut Vec<String>, report: &mut ConversionReport) {
    out.push("! ── FIREWALL RULES ──────────────────────────────────────────────────".to_string());
    out.push("! ⚠ LOW CONFIDENCE: Generic bootstrap rules — NOT a production policy.".to_string());
    out.push("!   Option A (current): permissive — connectivity test only.".to_string());
    out.push("!   Option B (recommended): deny-by-default + explicit allow.".to_string());

    // VLAN-based policy hints — если знаем VLAN имена
    if !cfg.vlans.is_empty() {
        out.push("!".to_string());
        out.push("! SUGGESTED POLICY (based on detected VLANs):".to_string());
        for vlan in &cfg.vlans {
            if let Some(name) = &vlan.name {
                let nl = name.to_lowercase();
                let policy = if nl.contains("camera") || nl.contains("security") || nl.contains("cctv") {
                    "deny internet access, allow NVR/VMS only"
                } else if nl.contains("printer") || nl.contains("print") {
                    "allow from user VLANs, deny internet"
                } else if nl.contains("voice") || nl.contains("voip") || nl.contains("phone") {
                    "allow SIP/RTP, prioritize QoS"
                } else if nl.contains("guest") {
                    "allow internet only, deny internal"
                } else if nl.contains("mgmt") || nl.contains("management") {
                    "restrict to admin hosts only"
                } else {
                    "allow outbound, restrict inbound"
                };
                out.push(format!("!   VLAN {:4} {:20} → {}", vlan.id, name, policy));
            }
        }
        out.push("!   (implement above as explicit zone-pair rules after VLAN→subinterface migration)".to_string());
    }

    out.push("! ─────────────────────────────────────────────────────────────────────".to_string());

    out.push("security zone-pair LAN WAN".to_string());
    out.push(" rule 10  ! ⚠ BOOTSTRAP — restrict before production".to_string());
    out.push("  action permit".to_string());
    out.push("  enable".to_string());
    out.push("  exit".to_string());
    out.push(" exit".to_string());

    out.push("security zone-pair WAN self".to_string());
    out.push(" rule 10".to_string());
    out.push("  action permit".to_string());
    out.push("  match protocol tcp".to_string());
    out.push("  match destination-port 22".to_string());
    out.push("  enable".to_string());
    out.push("  exit".to_string());
    out.push(" rule 20".to_string());
    out.push("  action permit".to_string());
    out.push("  match protocol icmp".to_string());
    out.push("  enable".to_string());
    out.push("  exit".to_string());
    out.push(" exit".to_string());

    out.push("security zone-pair LAN self".to_string());
    out.push(" rule 10  ! ⚠ BOOTSTRAP — restrict before production".to_string());
    out.push("  action permit".to_string());
    out.push("  enable".to_string());
    out.push("  exit".to_string());
    out.push(" exit".to_string());
    out.push(String::new());

    report.add_manual("firewall.bootstrap", "# (no firewall in source config)",
        "LOW CONFIDENCE: Bootstrap firewall rules generated. NOT production policy.",
        Some("Replace with deny-by-default + explicit allow rules."));
}

fn render_architecture_summary(
    cfg: &NetworkConfig,
    cls: &[(&Interface, ZoneClassification)],
    risk: &netconv_core::report::RiskScore,
    out: &mut Vec<String>,
) {
    let has_vlans   = !cfg.vlans.is_empty();
    let has_l2      = cfg.interfaces.iter().any(|i| i.l2.is_some());
    let has_stp     = cfg.stp.is_some();
    let trunk_ct    = cls.iter().filter(|(_, z)| z.role == InterfaceRole::TrunkInterswitch).count();
    let access_ct   = cls.iter().filter(|(_, z)| matches!(z.role, InterfaceRole::AccessEndpoint { .. })).count();

    out.push("! ══════════════════════════════════════════════════════════════════".to_string());
    out.push("! ARCHITECTURE CHANGE ANALYSIS".to_string());
    out.push("! ══════════════════════════════════════════════════════════════════".to_string());
    out.push("!".to_string());

    if has_l2 || has_vlans {
        out.push("! SOURCE:  L2 managed switch".to_string());
        if has_vlans {
            out.push(format!("!   VLANs: {} ({} named)",
                cfg.vlans.len(), cfg.vlans.iter().filter(|v| v.name.is_some()).count()));
            for v in &cfg.vlans {
                out.push(format!("!     {:>4}: {}", v.id, v.name.as_deref().unwrap_or("(unnamed)")));
            }
        }
        if trunk_ct + access_ct > 0 {
            out.push(format!("!   Topology: hierarchical ({} trunk, {} access ports)", trunk_ct, access_ct));
        }
        if has_stp { out.push("!   Loop protection: STP (rapid-pvst)".to_string()); }
    } else {
        out.push("! SOURCE:  L3 router".to_string());
    }

    out.push("!".to_string());
    out.push("! TARGET:  Eltex ESR — L3 router + stateful firewall (zone-based)".to_string());
    out.push("!   L2 switching: NOT SUPPORTED".to_string());
    out.push("!".to_string());

    if has_l2 || has_vlans {
        out.push("! WHAT CHANGES:".to_string());

        if has_vlans {
            out.push(format!("!   • {} VLANs → single broadcast domain", cfg.vlans.len()));
            out.push("!     IMPACT: all hosts share one L2 domain, broadcast traffic increases,".to_string());
            out.push("!             security isolation between VLANs disappears".to_string());
            if cfg.vlans.iter().any(|v| v.name.as_deref().map(|n| {
                let n = n.to_lowercase(); n.contains("security") || n.contains("camera")
            }).unwrap_or(false)) {
                out.push("!             security cameras will share segment with workstations".to_string());
            }
            if cfg.interfaces.iter().any(|i| i.voice_vlan.is_some()) {
                out.push("!             voice/data separation disappears → QoS issues possible".to_string());
            }
        }

        if has_stp {
            out.push("!   • STP loop protection → REMOVED".to_string());
            out.push("!     IMPACT: no L2 loop prevention, one cable loop = broadcast storm".to_string());
            out.push("!             risk of network-wide outage".to_string());
        }

        if trunk_ct > 0 {
            out.push(format!("!   • {} trunk links → L3 only (no L2 switching)", trunk_ct));
            out.push("!     IMPACT: hierarchical topology → flat, inter-VLAN traffic now routed".to_string());
        }

        out.push("!".to_string());
        out.push(format!("! RISK LEVEL: {}", risk.level.label()));
        out.push("!".to_string());

        // QUICK SAFE MIGRATION PATH
        out.push("! ── QUICK SAFE MIGRATION PATH ──────────────────────────────────".to_string());
        out.push("! Step 1: DO NOT apply this config to production directly".to_string());
        out.push("! Step 2: Deploy Eltex MES (managed L2 switch)".to_string());
        out.push("!         Keep all VLAN segmentation on MES".to_string());
        out.push("!         MES uplink → ESR via trunk (all VLANs)".to_string());
        out.push("! Step 3: Configure ESR as L3 gateway only".to_string());
        out.push("!         One subinterface per VLAN for inter-VLAN routing".to_string());
        out.push("!         Zone-pair rules between VLANs for firewall policy".to_string());
        out.push("! Step 4: Re-run netconv on L3-only router config".to_string());
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

    let has_l2    = cfg.interfaces.iter().any(|i| i.l2.is_some());
    let has_vlans = !cfg.vlans.is_empty();

    if has_l2 || has_vlans {
        score += 40;
        reasons.push(format!("device class mismatch: L2 switch → L3 router ({} VLANs)", cfg.vlans.len()));
        recommendations.push("Deploy Eltex MES for L2, use ESR as L3 gateway only".to_string());
    }
    if has_vlans {
        score += 20;
        reasons.push(format!("{} VLANs → single broadcast domain", cfg.vlans.len()));
        recommendations.push("All hosts in one broadcast domain — security and performance impact".to_string());
    }
    if cfg.stp.is_some() {
        score += 15;
        reasons.push("L2 loop protection (STP) removed — broadcast storm risk".to_string());
        recommendations.push("Ensure upstream switch handles loop prevention".to_string());
    }
    score += 10;
    reasons.push("firewall policy auto-generated (no source firewall config)".to_string());
    recommendations.push("Review and harden zone-pair rules before production".to_string());

    let unknown_ct = cls.iter().filter(|(_, z)| z.zone == ZoneName::Unknown).count();
    if unknown_ct > 0 {
        score += (unknown_ct as u32).min(15);
        reasons.push(format!("{} interfaces require manual zone assignment", unknown_ct));
        recommendations.push("Classify all unresolved interfaces before applying".to_string());
    }
    let med_wan_ct = cls.iter().filter(|(_, z)| z.zone == ZoneName::Wan && z.confidence == ConfidenceLevel::Medium).count();
    if med_wan_ct > 0 {
        score += 15;
        reasons.push(format!("{} uncertain WAN classification(s) — may be management interface", med_wan_ct));
        recommendations.push("Verify medium-confidence WAN interfaces".to_string());
    }

    let level = match score { 0..=20=>RiskLevel::Low, 21..=40=>RiskLevel::Medium, 41..=70=>RiskLevel::High, _=>RiskLevel::Critical };

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
