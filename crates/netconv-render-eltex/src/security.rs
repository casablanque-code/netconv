use netconv_core::ir::*;
use netconv_core::report::{ConversionReport, RiskLevel, ConfidenceLevel};

/// Зона интерфейса с confidence и причиной
#[derive(Debug, Clone)]
pub struct ZoneClassification {
    pub zone: ZoneName,
    pub confidence: ConfidenceLevel,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ZoneName {
    Lan,
    Wan,
}

impl ZoneName {
    pub fn as_str(&self) -> &str {
        match self { ZoneName::Lan => "LAN", ZoneName::Wan => "WAN" }
    }
}

/// Классификация зоны интерфейса с explicit confidence:
///
/// HIGH confidence:
///   - NAT outside → WAN
///   - description содержит uplink/wan/isp/internet/external → WAN
///
/// MEDIUM confidence:
///   - default route next-hop доступен через этот интерфейс → WAN
///     (может быть management interface!)
///
/// LOW confidence (fallback):
///   - всё остальное → LAN
pub fn classify_zone(iface: &Interface, cfg: &NetworkConfig) -> ZoneClassification {
    // HIGH: NAT outside — явный признак WAN
    if iface.nat_direction == Some(NatDirection::Outside) {
        return ZoneClassification {
            zone: ZoneName::Wan,
            confidence: ConfidenceLevel::High,
            reason: "nat outside configured".to_string(),
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
                };
            }
        }
    }

    // MEDIUM: default route next-hop на этом интерфейсе
    // Риск: это может быть management interface, не WAN uplink
    for route in &cfg.routing.static_routes {
        if route.prefix.to_string() == "0.0.0.0/0" {
            if let Some(addr) = iface.addresses.first() {
                if let NextHop::Ip(nh) = &route.next_hop {
                    if addr.prefix.contains(nh) {
                        let is_vlan1 = matches!(&iface.name.kind, InterfaceKind::Vlan)
                            && iface.name.id == "1";
                        let risk_note = if is_vlan1 {
                            "VLAN1 with default route — likely management interface, NOT WAN uplink"
                        } else {
                            "default route next-hop reachable via this interface"
                        };
                        return ZoneClassification {
                            zone: ZoneName::Wan,
                            confidence: ConfidenceLevel::Medium,
                            reason: risk_note.to_string(),
                        };
                    }
                }
            }
        }
    }

    // Loopback → всегда LAN, HIGH confidence
    if iface.name.kind == InterfaceKind::Loopback {
        return ZoneClassification {
            zone: ZoneName::Lan,
            confidence: ConfidenceLevel::High,
            reason: "loopback interface".to_string(),
        };
    }

    // LOW: fallback → LAN
    ZoneClassification {
        zone: ZoneName::Lan,
        confidence: ConfidenceLevel::Low,
        reason: "default classification".to_string(),
    }
}

pub fn render_security_zones(cfg: &NetworkConfig, out: &mut Vec<String>, report: &mut ConversionReport) {
    let classifications: Vec<(&Interface, ZoneClassification)> = cfg.interfaces.iter()
        .map(|i| (i, classify_zone(i, cfg)))
        .collect();

    let has_wan = classifications.iter().any(|(_, z)| z.zone == ZoneName::Wan);
    let has_lan = classifications.iter().any(|(_, z)| z.zone == ZoneName::Lan);

    // Считаем Risk Score для этой конвертации
    compute_risk_score(cfg, &classifications, report);

    out.push("!".to_string());
    out.push("! Security zones".to_string());

    if has_lan {
        out.push("security zone LAN".to_string());
        out.push(" exit".to_string());
    }
    if has_wan {
        out.push("security zone WAN".to_string());
        out.push(" exit".to_string());
    }
    out.push(String::new());

    // INTERFACE ROLE INFERENCE — явная таблица с confidence
    out.push("! ── INTERFACE ROLE INFERENCE ───────────────────────────────────".to_string());
    for (iface, cls) in &classifications {
        let conf_icon = match cls.confidence {
            ConfidenceLevel::High   => "✓",
            ConfidenceLevel::Medium => "~",
            ConfidenceLevel::Low    => "?",
        };
        out.push(format!("! {} {:30} → {}  [confidence: {}]  ({})",
            conf_icon,
            iface.name.original,
            cls.zone.as_str(),
            cls.confidence.label(),
            cls.reason,
        ));

        // Специальное предупреждение для MEDIUM confidence WAN
        if cls.zone == ZoneName::Wan && cls.confidence == ConfidenceLevel::Medium {
            out.push(format!("!   ⚠ RISK: {} may be a management interface, not WAN uplink.",
                iface.name.original));
            out.push("!   ⚠ Placing management in WAN zone may expose it to external traffic.".to_string());
            out.push("!   ⚠ Verify before applying. Consider moving to a separate MGMT zone.".to_string());
        }
    }
    out.push("! ────────────────────────────────────────────────────────────────".to_string());
    out.push(String::new());

    // Firewall rules с explicit LOW CONFIDENCE warning
    if has_wan && has_lan {
        render_basic_firewall(out, report);
    }

    // Репорт: WAN с medium/low confidence → warn
    for (iface, cls) in &classifications {
        if cls.zone == ZoneName::Wan {
            let msg = format!(
                "Interface {} → WAN [confidence: {}] — {}",
                iface.name.original, cls.confidence.label(), cls.reason
            );
            match cls.confidence {
                ConfidenceLevel::High => {
                    report.add_approximate("security_zone.wan", &format!("interface {}", iface.name.original), "WAN", &msg);
                }
                ConfidenceLevel::Medium | ConfidenceLevel::Low => {
                    report.add_manual("security_zone.wan.uncertain",
                        &format!("interface {}", iface.name.original),
                        &msg,
                        Some("Verify this is actually a WAN interface before applying"));
                }
            }
        }
    }

    report.add_approximate(
        "security_zones",
        "# (Cisco IOS has no security zones)",
        if has_wan { "security zone LAN + WAN" } else { "security zone LAN" },
        "ESR requires security zones. Classifications above — verify all before applying.",
    );
}

fn render_basic_firewall(out: &mut Vec<String>, report: &mut ConversionReport) {
    out.push("! ── FIREWALL RULES ─────────────────────────────────────────────".to_string());
    out.push("! ⚠ LOW CONFIDENCE: These are generic bootstrap rules.".to_string());
    out.push("!   They are NOT a production security policy.".to_string());
    out.push("!   Replace with site-specific rules before deploying.".to_string());
    out.push("!".to_string());
    out.push("!   Option A — current (permissive, for initial connectivity test):".to_string());
    out.push("!     LAN → WAN: permit all".to_string());
    out.push("!     WAN → self: permit SSH + ICMP".to_string());
    out.push("!     LAN → self: permit all".to_string());
    out.push("!".to_string());
    out.push("!   Option B — strict (deny by default, recommended for production):".to_string());
    out.push("!     Remove all permit rules below.".to_string());
    out.push("!     Add explicit rules for required traffic only.".to_string());
    out.push("!     Example: allow only HTTPS outbound from specific hosts.".to_string());
    out.push("! ────────────────────────────────────────────────────────────────".to_string());

    out.push("security zone-pair LAN WAN".to_string());
    out.push(" rule 10  ! ⚠ BOOTSTRAP: permit all outbound — restrict before production".to_string());
    out.push("  action permit".to_string());
    out.push("  enable".to_string());
    out.push("  exit".to_string());
    out.push(" exit".to_string());

    out.push("security zone-pair WAN self".to_string());
    out.push(" rule 10  ! permit SSH for management".to_string());
    out.push("  action permit".to_string());
    out.push("  match protocol tcp".to_string());
    out.push("  match destination-port 22".to_string());
    out.push("  enable".to_string());
    out.push("  exit".to_string());
    out.push(" rule 20  ! permit ICMP for diagnostics".to_string());
    out.push("  action permit".to_string());
    out.push("  match protocol icmp".to_string());
    out.push("  enable".to_string());
    out.push("  exit".to_string());
    out.push(" exit".to_string());

    out.push("security zone-pair LAN self".to_string());
    out.push(" rule 10  ! ⚠ BOOTSTRAP: permit all from LAN — restrict before production".to_string());
    out.push("  action permit".to_string());
    out.push("  enable".to_string());
    out.push("  exit".to_string());
    out.push(" exit".to_string());
    out.push(String::new());

    report.add_manual(
        "firewall.bootstrap",
        "# (no firewall in source Cisco IOS config)",
        "LOW CONFIDENCE: Bootstrap firewall rules generated. \
         NOT a production security policy. Replace before deploying.",
        Some("Option A: current permissive rules for initial test. \
              Option B: deny-by-default with explicit allow rules."),
    );
}

/// Вычисляем Risk Score для всей конвертации
fn compute_risk_score(
    cfg: &NetworkConfig,
    classifications: &[(&Interface, ZoneClassification)],
    report: &mut ConversionReport,
) {
    let mut reasons: Vec<String> = vec![];
    let mut recommendations: Vec<String> = vec![];
    let mut score: u32 = 0;

    // Device class mismatch — свитч конвертируется в роутер
    let has_l2 = cfg.interfaces.iter().any(|i| i.l2.is_some());
    let has_vlans = !cfg.vlans.is_empty();
    if has_l2 || has_vlans {
        score += 40;
        reasons.push("device class mismatch: source is L2 switch, target is L3 router/firewall".to_string());
        recommendations.push("Consider Eltex MES series for L2 features, use ESR as L3 gateway only".to_string());
    }

    // VLAN segmentation loss
    if has_vlans {
        score += 20;
        reasons.push(format!("loss of VLAN segmentation ({} VLANs)", cfg.vlans.len()));
        recommendations.push("All hosts will be in one broadcast domain — security impact".to_string());
    }

    // Firewall policy inferred (нет исходного firewall в IOS)
    score += 15;
    reasons.push("firewall policy inferred — no source firewall config to migrate".to_string());
    recommendations.push("Review and harden generated zone-pair rules before production deployment".to_string());

    // Medium confidence zone classifications
    let medium_wan: Vec<_> = classifications.iter()
        .filter(|(_, z)| z.zone == ZoneName::Wan && z.confidence == ConfidenceLevel::Medium)
        .collect();
    if !medium_wan.is_empty() {
        score += 15;
        for (iface, cls) in &medium_wan {
            reasons.push(format!("uncertain WAN classification: {} ({})",
                iface.name.original, cls.reason));
        }
        recommendations.push("Verify WAN interface assignments — medium confidence zones may be management interfaces".to_string());
    }

    // STP/storm-control loss
    if cfg.stp.is_some() {
        score += 10;
        reasons.push("L2 loop protection (STP) not migrated".to_string());
        recommendations.push("Ensure upstream switch handles loop prevention".to_string());
    }

    let level = match score {
        0..=20  => RiskLevel::Low,
        21..=45 => RiskLevel::Medium,
        46..=75 => RiskLevel::High,
        _       => RiskLevel::Critical,
    };

    report.risk = netconv_core::report::RiskScore { level, reasons, recommendations };
}

pub fn render_risk_score_comment(
    risk: &netconv_core::report::RiskScore,
    out: &mut Vec<String>,
) {
    out.push("! ══════════════════════════════════════════════════════════════".to_string());
    out.push(format!("! RISK SCORE: {}", risk.level.label()));
    out.push("!".to_string());
    if !risk.reasons.is_empty() {
        out.push("! Reasons:".to_string());
        for r in &risk.reasons {
            out.push(format!("!   - {}", r));
        }
    }
    if !risk.recommendations.is_empty() {
        out.push("!".to_string());
        out.push("! Recommendations:".to_string());
        for r in &risk.recommendations {
            out.push(format!("!   → {}", r));
        }
    }
    out.push("! ══════════════════════════════════════════════════════════════".to_string());
    out.push(String::new());
}


