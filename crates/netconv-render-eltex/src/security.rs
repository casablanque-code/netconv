use netconv_core::ir::*;
use netconv_core::report::{ConversionReport, RiskLevel, ConfidenceLevel};

/// Зона интерфейса с confidence и причиной
#[derive(Debug, Clone)]
pub struct ZoneClassification {
    pub zone: ZoneName,
    pub confidence: ConfidenceLevel,
    pub reason: String,
    pub role: InterfaceRole,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ZoneName {
    Lan,
    Wan,
    Unknown,
}

impl ZoneName {
    pub fn as_str(&self) -> &str {
        match self {
            ZoneName::Lan     => "LAN",
            ZoneName::Wan     => "WAN",
            ZoneName::Unknown => "LAN", // fallback для генерации конфига
        }
    }
}

/// Роль интерфейса — для архитектурного анализа
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
}

pub fn classify_zone(iface: &Interface, cfg: &NetworkConfig) -> ZoneClassification {
    // HIGH: NAT outside
    if iface.nat_direction == Some(NatDirection::Outside) {
        return ZoneClassification {
            zone: ZoneName::Wan,
            confidence: ConfidenceLevel::High,
            reason: "nat outside configured".to_string(),
            role: InterfaceRole::WanUplink,
        };
    }

    // HIGH: description содержит WAN-маркеры
    if let Some(desc) = &iface.description {
        let d = desc.to_lowercase();
        let wan_kw = ["uplink", "wan", "isp", "internet", "external",
                      "provider", "upstream", "transit", "peering"];
        for kw in &wan_kw {
            if d.contains(kw) {
                return ZoneClassification {
                    zone: ZoneName::Wan,
                    confidence: ConfidenceLevel::High,
                    reason: format!("description contains '{}'", kw),
                    role: InterfaceRole::WanUplink,
                };
            }
        }
    }

    // MEDIUM: default route next-hop на этом интерфейсе
    for route in &cfg.routing.static_routes {
        if route.prefix.to_string() == "0.0.0.0/0" {
            if let Some(addr) = iface.addresses.first() {
                if let NextHop::Ip(nh) = &route.next_hop {
                    if addr.prefix.contains(nh) {
                        let is_vlan1 = matches!(&iface.name.kind, InterfaceKind::Vlan)
                            && iface.name.id == "1";
                        return ZoneClassification {
                            zone: ZoneName::Wan,
                            confidence: ConfidenceLevel::Medium,
                            reason: if is_vlan1 {
                                "default route via VLAN1 — likely management, NOT WAN".to_string()
                            } else {
                                "default route next-hop reachable via this interface".to_string()
                            },
                            role: if is_vlan1 {
                                InterfaceRole::ManagementSuspected
                            } else {
                                InterfaceRole::WanUplink
                            },
                        };
                    }
                }
            }
        }
    }

    // Loopback
    if iface.name.kind == InterfaceKind::Loopback {
        return ZoneClassification {
            zone: ZoneName::Lan,
            confidence: ConfidenceLevel::High,
            reason: "loopback interface".to_string(),
            role: InterfaceRole::Loopback,
        };
    }

    // L2 анализ — trunk vs access
    if let Some(l2) = &iface.l2 {
        match l2.mode {
            L2Mode::Trunk => {
                return ZoneClassification {
                    zone: ZoneName::Unknown,
                    confidence: ConfidenceLevel::Low,
                    reason: "trunk port — inter-switch link, zone requires manual assignment".to_string(),
                    role: InterfaceRole::TrunkInterswitch,
                };
            }
            L2Mode::Access => {
                let vlan = l2.access_vlan;
                return ZoneClassification {
                    zone: ZoneName::Unknown,
                    confidence: ConfidenceLevel::Low,
                    reason: format!("access port{}",
                        vlan.map(|v| format!(" VLAN {}", v)).unwrap_or_default()),
                    role: InterfaceRole::AccessEndpoint { vlan },
                };
            }
        }
    }

    // Полностью неизвестно
    ZoneClassification {
        zone: ZoneName::Unknown,
        confidence: ConfidenceLevel::Low,
        reason: "no classification signals — manual assignment required".to_string(),
        role: InterfaceRole::Unknown,
    }
}

pub fn render_security_zones(cfg: &NetworkConfig, out: &mut Vec<String>, report: &mut ConversionReport) {
    let classifications: Vec<(&Interface, ZoneClassification)> = cfg.interfaces.iter()
        .map(|i| (i, classify_zone(i, cfg)))
        .collect();

    let has_wan  = classifications.iter().any(|(_, z)| z.zone == ZoneName::Wan);
    let _has_lan = true; // всегда нужна LAN зона
    let unknown_count = classifications.iter().filter(|(_, z)| z.zone == ZoneName::Unknown).count();
    let access_count  = classifications.iter().filter(|(_, z)| z.role == InterfaceRole::AccessEndpoint { vlan: z.role.access_vlan() }).count();
    let trunk_count   = classifications.iter().filter(|(_, z)| z.role == InterfaceRole::TrunkInterswitch).count();

    // Risk Score
    compute_risk_score(cfg, &classifications, report);

    // ARCHITECTURE CHANGE SUMMARY — самый первый блок
    render_architecture_summary(cfg, &classifications, &report.risk.clone(), out);

    out.push("!".to_string());
    out.push("! Security zones".to_string());
    out.push("security zone LAN".to_string());
    out.push(" exit".to_string());
    if has_wan {
        out.push("security zone WAN".to_string());
        out.push(" exit".to_string());
    }
    out.push(String::new());

    // INTERFACE ROLE INFERENCE
    out.push("! ── INTERFACE ROLE INFERENCE ───────────────────────────────────────".to_string());

    if unknown_count > 0 {
        out.push("!".to_string());
        out.push(format!("! {} interfaces require manual zone assignment:", unknown_count));
        if access_count > 0 {
            out.push(format!("!   - {} access ports (VLAN-based) → likely LAN endpoints", access_count));
            out.push("!     Assign to LAN zone, or create separate VLAN zones with MSTP.".to_string());
        }
        if trunk_count > 0 {
            out.push(format!("!   - {} trunk/inter-switch ports → uplinks or downlinks", trunk_count));
            out.push("!     If connecting to upstream router → WAN.".to_string());
            out.push("!     If connecting to downstream switch → LAN (or separate zone).".to_string());
        }
        out.push("!".to_string());
    }

    for (iface, cls) in &classifications {
        let conf_icon = match cls.confidence {
            ConfidenceLevel::High   => "✓ HIGH  ",
            ConfidenceLevel::Medium => "~ MEDIUM",
            ConfidenceLevel::Low    => "? UNKNWN",
        };
        let zone_str = match &cls.zone {
            ZoneName::Wan     => "WAN",
            ZoneName::Lan     => "LAN",
            ZoneName::Unknown => "??? (manual)",
        };
        out.push(format!("! [{}] {:28} → {:14} role: {}",
            conf_icon, iface.name.original, zone_str, cls.role.label()));

        if cls.zone == ZoneName::Wan && cls.confidence == ConfidenceLevel::Medium {
            out.push(format!("!           ⚠ RISK: {} — {}", iface.name.original, cls.reason));
            out.push("!           ⚠ Placing management in WAN may expose it externally.".to_string());
        }
    }
    out.push("! ────────────────────────────────────────────────────────────────────".to_string());
    out.push(String::new());

    if has_wan {
        render_basic_firewall(out, report);
    }

    // Report items
    for (iface, cls) in &classifications {
        match (&cls.zone, &cls.confidence) {
            (ZoneName::Wan, ConfidenceLevel::High) => {
                report.add_approximate("security_zone",
                    &format!("interface {}", iface.name.original), "WAN",
                    &format!("WAN [HIGH]: {}", cls.reason));
            }
            (ZoneName::Wan, _) => {
                report.add_manual("security_zone.uncertain",
                    &format!("interface {}", iface.name.original),
                    &format!("WAN classification uncertain [{}]: {}", cls.confidence.label(), cls.reason),
                    Some("Verify this is WAN before applying"));
            }
            (ZoneName::Unknown, _) => {
                report.add_manual("security_zone.unknown",
                    &format!("interface {}", iface.name.original),
                    &format!("Zone unknown — {}", cls.reason),
                    Some("Assign manually to LAN or WAN based on network topology"));
            }
            _ => {
                report.add_approximate("security_zone",
                    &format!("interface {}", iface.name.original), "LAN",
                    &format!("LAN [{}]: {}", cls.confidence.label(), cls.reason));
            }
        }
    }
}

fn render_architecture_summary(
    cfg: &NetworkConfig,
    classifications: &[(&Interface, ZoneClassification)],
    risk: &netconv_core::report::RiskScore,
    out: &mut Vec<String>,
) {
    let has_vlans    = !cfg.vlans.is_empty();
    let has_l2       = cfg.interfaces.iter().any(|i| i.l2.is_some());
    let has_stp      = cfg.stp.is_some();
    let trunk_count  = classifications.iter().filter(|(_, z)| z.role == InterfaceRole::TrunkInterswitch).count();
    let access_count = classifications.iter().filter(|(_, z)| matches!(z.role, InterfaceRole::AccessEndpoint { .. })).count();
    let vlan_count   = cfg.vlans.len();

    out.push("! ══════════════════════════════════════════════════════════════════".to_string());
    out.push("! ARCHITECTURE CHANGE ANALYSIS".to_string());
    out.push("! ══════════════════════════════════════════════════════════════════".to_string());
    out.push("!".to_string());
    out.push("! SOURCE DEVICE:".to_string());
    if has_l2 || has_vlans {
        out.push("!   Type:      L2 managed switch (VLAN-based segmentation)".to_string());
        if vlan_count > 0 {
            out.push(format!("!   VLANs:     {} ({} named)",
                vlan_count,
                cfg.vlans.iter().filter(|v| v.name.is_some()).count()));
        }
        if trunk_count > 0 {
            out.push(format!("!   Topology:  hierarchical ({} trunk links, {} access ports)",
                trunk_count, access_count));
        }
        if has_stp {
            out.push("!   Loop prot: STP (spanning-tree rapid-pvst)".to_string());
        }
    } else {
        out.push("!   Type:      L3 router".to_string());
    }
    out.push("!".to_string());
    out.push("! TARGET DEVICE:".to_string());
    out.push("!   Type:      L3 router + stateful firewall (zone-based policy)".to_string());
    out.push("!   Model:     Eltex ESR".to_string());
    out.push("!   L2 switch: NOT supported".to_string());
    out.push("!".to_string());

    if has_l2 || has_vlans {
        out.push("! WHAT CHANGES:".to_string());
        out.push("!".to_string());

        if has_vlans {
            out.push(format!("!   VLAN segmentation ({} VLANs) → single broadcast domain", vlan_count));
            out.push("!   IMPACT:".to_string());
            out.push("!     - All hosts merged into one L2 domain".to_string());
            out.push("!     - Broadcast traffic increases proportionally".to_string());
            out.push("!     - Security isolation between VLANs disappears".to_string());
            if cfg.vlans.iter().any(|v| v.name.as_deref().map(|n| n.to_lowercase().contains("security") || n.to_lowercase().contains("camera")).unwrap_or(false)) {
                out.push("!     - Security cameras will share network with workstations".to_string());
            }
            if cfg.interfaces.iter().any(|i| i.voice_vlan.is_some()) {
                out.push("!     - Voice/data separation disappears → QoS issues possible".to_string());
            }
            out.push("!".to_string());
        }

        if has_stp {
            out.push("!   STP loop prevention → REMOVED".to_string());
            out.push("!   IMPACT:".to_string());
            out.push("!     - No protection against L2 loops".to_string());
            out.push("!     - A single cable loop can cause network-wide broadcast storm".to_string());
            out.push("!     - Risk: complete network outage".to_string());
            out.push("!".to_string());
        }

        if trunk_count > 0 {
            out.push(format!("!   {} trunk links → flattened (L3 routing only)", trunk_count));
            out.push("!   IMPACT:".to_string());
            out.push("!     - Hierarchical L2 topology replaced by flat L3".to_string());
            out.push("!     - Inter-VLAN traffic now routed (not switched) → latency".to_string());
            out.push("!".to_string());
        }

        out.push("! RECOMMENDATION:".to_string());
        out.push("!   Option 1 (RECOMMENDED): Hybrid architecture".to_string());
        out.push("!     Keep L2 switching on Eltex MES (managed switch)".to_string());
        out.push("!     Use ESR as L3 gateway and firewall only".to_string());
        out.push("!     MES connects to ESR via trunk → ESR does inter-VLAN routing".to_string());
        out.push("!".to_string());
        out.push("!   Option 2: Pure ESR (subinterfaces)".to_string());
        out.push("!     Use dot1q subinterfaces for inter-VLAN routing".to_string());
        out.push("!     External unmanaged switch for L2 — no VLAN isolation".to_string());
        out.push("!     Suitable only if VLAN segmentation is not a security requirement".to_string());
    }

    out.push("!".to_string());
    out.push(format!("! RISK LEVEL: {}", risk.level.label()));
    if !risk.reasons.is_empty() {
        out.push("! Factors:".to_string());
        for r in &risk.reasons {
            out.push(format!("!   - {}", r));
        }
    }
    out.push("! ══════════════════════════════════════════════════════════════════".to_string());
    out.push(String::new());
}

fn render_basic_firewall(out: &mut Vec<String>, report: &mut ConversionReport) {
    out.push("! ── FIREWALL RULES ──────────────────────────────────────────────────".to_string());
    out.push("! ⚠ LOW CONFIDENCE: Generic bootstrap rules — NOT a production policy.".to_string());
    out.push("!   Option A (current): permissive — use for initial connectivity test only.".to_string());
    out.push("!   Option B (recommended): replace with deny-by-default + explicit allow.".to_string());
    out.push("! ─────────────────────────────────────────────────────────────────────".to_string());

    out.push("security zone-pair LAN WAN".to_string());
    out.push(" rule 10  ! ⚠ BOOTSTRAP ONLY — restrict before production".to_string());
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
    out.push(" rule 10  ! ⚠ BOOTSTRAP ONLY".to_string());
    out.push("  action permit".to_string());
    out.push("  enable".to_string());
    out.push("  exit".to_string());
    out.push(" exit".to_string());
    out.push(String::new());

    report.add_manual(
        "firewall.bootstrap",
        "# (no firewall in source config)",
        "LOW CONFIDENCE: Bootstrap rules generated. NOT production policy.",
        Some("Replace with deny-by-default + explicit allow rules before deploying."),
    );
}

fn compute_risk_score(
    cfg: &NetworkConfig,
    classifications: &[(&Interface, ZoneClassification)],
    report: &mut ConversionReport,
) {
    let mut reasons: Vec<String> = vec![];
    let mut recommendations: Vec<String> = vec![];
    let mut score: u32 = 0;

    let has_l2    = cfg.interfaces.iter().any(|i| i.l2.is_some());
    let has_vlans = !cfg.vlans.is_empty();

    if has_l2 || has_vlans {
        score += 40;
        reasons.push(format!(
            "device class mismatch: L2 switch → L3 router ({} VLANs, {} L2 interfaces)",
            cfg.vlans.len(),
            cfg.interfaces.iter().filter(|i| i.l2.is_some()).count()
        ));
        recommendations.push("Use Eltex MES as L2 switch, ESR as L3 gateway only".to_string());
    }

    if has_vlans {
        score += 20;
        reasons.push(format!("loss of VLAN segmentation ({} VLANs → single broadcast domain)", cfg.vlans.len()));
        recommendations.push("All hosts will share one broadcast domain — security and performance impact".to_string());
    }

    if cfg.stp.is_some() {
        score += 15;
        reasons.push("L2 loop prevention (STP) removed — broadcast storm risk".to_string());
        recommendations.push("Ensure upstream switch handles loop prevention".to_string());
    }

    // Firewall inferred
    score += 10;
    reasons.push("firewall policy auto-generated — no source firewall to migrate".to_string());
    recommendations.push("Review and harden zone-pair rules before production".to_string());

    // Uncertain zone classifications
    let uncertain: Vec<_> = classifications.iter()
        .filter(|(_, z)| z.zone == ZoneName::Unknown || z.confidence == ConfidenceLevel::Low)
        .collect();
    if !uncertain.is_empty() {
        score += uncertain.len() as u32 * 2;
        reasons.push(format!("{} interfaces require manual zone assignment", uncertain.len()));
        recommendations.push("Classify unresolved interfaces before applying config".to_string());
    }

    let medium_wan: Vec<_> = classifications.iter()
        .filter(|(_, z)| z.zone == ZoneName::Wan && z.confidence == ConfidenceLevel::Medium)
        .collect();
    if !medium_wan.is_empty() {
        score += 15;
        for (iface, cls) in &medium_wan {
            reasons.push(format!("uncertain WAN: {} ({})", iface.name.original, cls.reason));
        }
        recommendations.push("Verify medium-confidence WAN interfaces — may be management".to_string());
    }

    let level = match score {
        0..=20  => RiskLevel::Low,
        21..=40 => RiskLevel::Medium,
        41..=70 => RiskLevel::High,
        _       => RiskLevel::Critical,
    };

    report.risk = netconv_core::report::RiskScore { level, reasons, recommendations };
}

pub fn render_risk_score_comment(
    risk: &netconv_core::report::RiskScore,
    out: &mut Vec<String>,
) {
    out.push("! ══════════════════════════════════════════════════════════════════".to_string());
    out.push(format!("! FINAL RISK SCORE: {}", risk.level.label()));
    if !risk.reasons.is_empty() {
        out.push("! Factors:".to_string());
        for r in &risk.reasons { out.push(format!("!   - {}", r)); }
    }
    if !risk.recommendations.is_empty() {
        out.push("! Actions required:".to_string());
        for r in &risk.recommendations { out.push(format!("!   → {}", r)); }
    }
    out.push("! ══════════════════════════════════════════════════════════════════".to_string());
    out.push(String::new());
}

// Helper для access_vlan из InterfaceRole
impl InterfaceRole {
    fn access_vlan(&self) -> Option<u16> {
        if let InterfaceRole::AccessEndpoint { vlan } = self { *vlan } else { None }
    }
}
