use netconv_core::ir::*;
use netconv_core::report::ConversionReport;

/// Зона интерфейса с причиной классификации
#[derive(Debug, Clone, PartialEq)]
pub enum IfaceZone {
    Lan,
    Wan { reason: String },
}

/// Эвристика классификации зон (в порядке приоритета):
/// 1. NAT outside → WAN
/// 2. Description содержит uplink/wan/isp/internet/external → WAN
/// 3. Default route через этот интерфейс → WAN
/// 4. Loopback/NAT inside/OSPF → LAN
/// 5. Всё остальное → LAN
pub fn classify_zone(iface: &Interface, cfg: &NetworkConfig) -> IfaceZone {
    // 1. NAT outside — явный WAN
    if iface.nat_direction == Some(NatDirection::Outside) {
        return IfaceZone::Wan { reason: "nat outside".to_string() };
    }

    // 2. Description содержит WAN-маркеры
    if let Some(desc) = &iface.description {
        let d = desc.to_lowercase();
        let wan_kw = ["uplink", "wan", "isp", "internet", "external",
                      "provider", "upstream", "transit", "peering"];
        for kw in &wan_kw {
            if d.contains(kw) {
                return IfaceZone::Wan {
                    reason: format!("description contains '{}'", kw)
                };
            }
        }
    }

    // 3. Default route next-hop на этом интерфейсе
    for route in &cfg.routing.static_routes {
        if route.prefix.to_string() == "0.0.0.0/0" {
            if let Some(addr) = iface.addresses.first() {
                if let NextHop::Ip(nh) = &route.next_hop {
                    if addr.prefix.contains(nh) {
                        return IfaceZone::Wan {
                            reason: "default route next-hop reachable via this interface".to_string()
                        };
                    }
                }
            }
        }
    }

    // 4. Loopback → всегда LAN
    if iface.name.kind == InterfaceKind::Loopback {
        return IfaceZone::Lan;
    }

    IfaceZone::Lan
}

pub fn render_security_zones(cfg: &NetworkConfig, out: &mut Vec<String>, report: &mut ConversionReport) {
    let zones: Vec<(&Interface, IfaceZone)> = cfg.interfaces.iter()
        .map(|i| (i, classify_zone(i, cfg)))
        .collect();

    let has_wan = zones.iter().any(|(_, z)| matches!(z, IfaceZone::Wan { .. }));
    let has_lan = zones.iter().any(|(_, z)| *z == IfaceZone::Lan);

    out.push("!".to_string());
    out.push("! Security zones (heuristic — review before applying)".to_string());

    if has_lan {
        out.push("security zone LAN".to_string());
        out.push(" exit".to_string());
    }
    if has_wan {
        out.push("security zone WAN".to_string());
        out.push(" exit".to_string());
    }
    out.push(String::new());

    // Явный список классификации — engineer видит что и почему
    out.push("! Zone assignment summary:".to_string());
    for (iface, zone) in &zones {
        match zone {
            IfaceZone::Wan { reason } => {
                out.push(format!("! ⚠ ASSUMPTION: {} → WAN  (reason: {})",
                    iface.name.original, reason));
            }
            IfaceZone::Lan => {
                out.push(format!("!   {} → LAN", iface.name.original));
            }
        }
    }
    out.push(String::new());

    if has_wan && has_lan {
        render_basic_firewall(out, report);
    }

    // WAN assumptions → repорт
    for (iface, zone) in &zones {
        if let IfaceZone::Wan { reason } = zone {
            report.add_approximate(
                "security_zone.wan",
                &format!("interface {}", iface.name.original),
                "security-zone WAN",
                &format!("ASSUMPTION: {} → WAN ({}). Verify before applying.",
                    iface.name.original, reason),
            );
        }
    }

    report.add_approximate(
        "security_zones",
        "# (Cisco IOS has no security zones)",
        if has_wan { "security zone LAN + WAN" } else { "security zone LAN" },
        "ESR requires security zones on all interfaces. \
         Classified heuristically — review all assignments.",
    );
}

fn render_basic_firewall(out: &mut Vec<String>, report: &mut ConversionReport) {
    out.push("!".to_string());
    out.push("! Basic firewall rules (auto-generated — review carefully)".to_string());

    out.push("security zone-pair LAN WAN".to_string());
    out.push(" rule 10".to_string());
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
    out.push(" rule 10".to_string());
    out.push("  action permit".to_string());
    out.push("  enable".to_string());
    out.push("  exit".to_string());
    out.push(" exit".to_string());
    out.push(String::new());

    report.add_approximate(
        "firewall",
        "# (Cisco IOS ACL rules not migrated)",
        "zone-pair LAN WAN / WAN self / LAN self",
        "Basic rules: LAN→WAN permit all, WAN→self SSH+ICMP, LAN→self permit all. \
         Tighten according to security policy.",
    );
}
