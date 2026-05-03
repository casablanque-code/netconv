use netconv_core::ir::*;
use netconv_core::report::ConversionReport;

pub fn render_nat(cfg: &NetworkConfig, out: &mut Vec<String>, report: &mut ConversionReport) {
    if cfg.nat.is_empty() { return; }

    out.push("#".to_string());
    out.push("# NAT configuration".to_string());
    out.push("# NOTE: На VRP NAT привязывается к интерфейсу через 'nat outbound'".to_string());
    out.push("# Убедись что интерфейс WAN правильно идентифицирован".to_string());
    out.push(String::new());

    for (i, rule) in cfg.nat.iter().enumerate() {
        match &rule.rule_type {
            NatType::Overload => render_nat_overload(rule, i, cfg, out, report),
            NatType::Dynamic  => render_nat_dynamic(rule, i, out, report),
            NatType::Static   => render_nat_static(rule, out, report),
        }
    }
}

fn render_nat_overload(
    rule: &NatRule,
    idx: usize,
    cfg: &NetworkConfig,
    out: &mut Vec<String>,
    report: &mut ConversionReport,
) {
    // Cisco PAT: ip nat inside source list ACL interface Gi0/0 overload
    // VRP PAT:   nat outbound <acl-number|name> interface  (на WAN интерфейсе)

    let acl_ref = rule.acl.as_deref().unwrap_or("ACL_UNKNOWN");

    // Находим WAN интерфейс (nat outside)
    let wan_iface = cfg.interfaces.iter()
        .find(|i| i.nat_direction == Some(NatDirection::Outside))
        .map(|i| crate::iface::ios_to_vrp_ifname(&i.name));

    if rule.interface_overload {
        if let Some(wan) = wan_iface {
            out.push(format!("# На интерфейсе {}:", wan));
            out.push(format!("interface {}", wan));
            out.push(format!(" nat outbound {}", acl_ref));
            report.add_approximate(
                "nat.overload",
                &format!("ip nat inside source list {} interface <WAN> overload", acl_ref),
                &format!("interface <WAN>\n nat outbound {}", acl_ref),
                "VRP NAT overload: 'nat outbound <acl>' на WAN интерфейсе. \
                 Также требуется 'nat enable' глобально.",
            );
        } else {
            out.push(format!("# MANUAL: ip nat inside source list {} interface <WAN> overload", acl_ref));
            out.push("# Определи WAN интерфейс и добавь 'nat outbound <acl>' на него".to_string());
            report.add_manual(
                "nat.overload",
                &format!("ip nat inside source list {} interface <WAN> overload", acl_ref),
                "WAN интерфейс не определён однозначно",
                Some("Добавь 'nat outbound <acl>' на WAN интерфейс вручную"),
            );
        }
    } else if let Some(pool) = &rule.pool {
        // NAT с пулом + overload
        let pool_start = pool.start;
        let pool_end = pool.end;
        out.push(format!("nat address-group {} {} {} no-pat", idx, pool_start, pool_end));
        out.push(format!("# На WAN интерфейсе: nat outbound {} address-group {}", acl_ref, idx));
        report.add_approximate(
            "nat.pool_overload",
            &format!("ip nat pool {} {} {} ... / ip nat inside source list {} pool {}", pool.name, pool_start, pool_end, acl_ref, pool.name),
            &format!("nat address-group {} {} {}", idx, pool_start, pool_end),
            "VRP: address-group + nat outbound на интерфейсе. Синтаксис существенно отличается.",
        );
    }

    out.push(String::new());
}

fn render_nat_dynamic(rule: &NatRule, idx: usize, out: &mut Vec<String>, report: &mut ConversionReport) {
    let acl_ref = rule.acl.as_deref().unwrap_or("ACL_UNKNOWN");

    if let Some(pool) = &rule.pool {
        out.push(format!("nat address-group {} {} {} no-pat", idx, pool.start, pool.end));
        out.push(format!("# На WAN интерфейсе: nat outbound {} address-group {}", acl_ref, idx));
        report.add_approximate(
            "nat.dynamic",
            &format!("ip nat inside source list {} pool {}", acl_ref, pool.name),
            &format!("nat address-group {} (+ nat outbound на интерфейсе)", idx),
            "VRP dynamic NAT: address-group определяет пул, nat outbound применяется на интерфейсе",
        );
    }
}

fn render_nat_static(rule: &NatRule, out: &mut Vec<String>, report: &mut ConversionReport) {
    if let Some(entry) = &rule.static_entry {
        // Cisco: ip nat inside source static 10.0.0.10 203.0.113.10
        // VRP:   nat static global <global> inside <local>   (на WAN интерфейсе)

        if let (Some(lport), Some(gport)) = (entry.local_port, entry.global_port) {
            // Port static NAT
            let proto = entry.protocol.as_ref()
                .map(|p| match p {
                    AclProtocol::Tcp => "tcp",
                    AclProtocol::Udp => "udp",
                    _ => "tcp",
                })
                .unwrap_or("tcp");

            out.push(format!(
                "# На WAN интерфейсе: nat static protocol {} global {} {} inside {} {}",
                proto, entry.global, gport, entry.local, lport
            ));
            report.add_approximate(
                "nat.static_port",
                &format!("ip nat inside source static {} {} {} {} {}",
                    proto, entry.local, lport, entry.global, gport),
                &format!("nat static protocol {} global {} {} inside {} {}", proto, entry.global, gport, entry.local, lport),
                "VRP static port NAT: команда на WAN интерфейсе. Порядок global/inside обратный.",
            );
        } else {
            out.push(format!("# На WAN интерфейсе: nat static global {} inside {}",
                entry.global, entry.local));
            report.add_approximate(
                "nat.static",
                &format!("ip nat inside source static {} {}", entry.local, entry.global),
                &format!("nat static global {} inside {}", entry.global, entry.local),
                "VRP static NAT: команда на WAN интерфейсе. Порядок: сначала global, потом inside.",
            );
        }
        out.push(String::new());
    }
}
