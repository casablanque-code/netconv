use netconv_core::ir::*;
use netconv_core::report::ConversionReport;

/// Рендерит тела ACL (access-list) для Eltex ESR.
///
/// До этого фикса cfg.acls вообще не использовался в Eltex-рендерере: на
/// интерфейсах генерировалась команда "ip access-group <name> in/out"
/// (см. iface.rs), но само тело списка — "ip access-list ... permit/deny"
/// — нигде не выводилось. Итоговый конфиг ссылался на несуществующий ACL.
///
/// ESR CLI в задокументированных в этом проекте местах (ip access-group,
/// ip helper-address, hostname) подтверждённо совпадает с синтаксисом
/// Cisco IOS (см. iface.rs:112,121,129 — "ESR: ... syntax matches Cisco").
/// Поэтому тело ACL рендерится в том же IOS-совместимом синтаксисе.
/// Это контрастирует с DNS/line vty (system.rs), для которых такого
/// прецедента в проекте не было — там осознанно выбран Manual, а не
/// предположение о совпадении синтаксиса.
pub fn render_acls(cfg: &NetworkConfig, out: &mut Vec<String>, report: &mut ConversionReport) {
    if cfg.acls.is_empty() { return; }

    for acl in &cfg.acls {
        render_acl(acl, out, report);
    }
}

fn render_acl(acl: &Acl, out: &mut Vec<String>, report: &mut ConversionReport) {
    let (acl_type_str, name_str) = match &acl.name {
        AclName::Named(name) => {
            let t = match acl.acl_type {
                AclType::Standard => "standard",
                AclType::Extended => "extended",
            };
            (t, name.clone())
        }
        AclName::Numbered(n) => {
            let t = match acl.acl_type {
                AclType::Standard => "standard",
                AclType::Extended => "extended",
            };
            (t, n.to_string())
        }
    };

    out.push("!".to_string());
    out.push(format!("ip access-list {} {}", acl_type_str, name_str));

    for entry in &acl.entries {
        if let Some(remark) = &entry.remark {
            out.push(format!(" remark {}", remark));
            continue;
        }

        let rule = render_acl_entry(entry, &acl.acl_type);
        out.push(format!(" {}", rule));

        let src = format_source_acl_entry(entry);
        report.add_approximate(
            "acl.entry",
            &src,
            &rule,
            "ESR ip access-list syntax matches Cisco IOS for entries already \
             verified in this tool (ip access-group on interfaces) — \
             verify sequence numbering and platform-specific keywords before applying.",
        );
    }

    out.push(" exit".to_string());
    out.push(String::new());
}

fn render_acl_entry(entry: &AclEntry, acl_type: &AclType) -> String {
    let seq = entry.sequence.map(|s| format!("{} ", s)).unwrap_or_default();
    let action = match entry.action {
        AclAction::Permit => "permit",
        AclAction::Deny   => "deny",
    };

    match acl_type {
        AclType::Standard => {
            let src = render_acl_match(&entry.src);
            format!("{}{} {}", seq, action, src)
        }
        AclType::Extended => {
            let proto = entry.protocol.as_ref().map(render_protocol).unwrap_or_else(|| "ip".to_string());
            let src = render_acl_match(&entry.src);
            let src_port = entry.src_port.as_ref()
                .map(|p| format!(" {}", render_port(p)))
                .unwrap_or_default();

            let dst = entry.dst.as_ref()
                .map(render_acl_match)
                .unwrap_or_else(|| "any".to_string());

            let dst_port = entry.dst_port.as_ref()
                .map(|p| format!(" {}", render_port(p)))
                .unwrap_or_default();

            let established = if entry.established { " established" } else { "" };
            let log = if entry.log { " log" } else { "" };

            format!(
                "{}{} {} {}{} {}{}{}{}",
                seq, action, proto, src, src_port, dst, dst_port, established, log
            )
        }
    }
}

fn render_acl_match(m: &AclMatch) -> String {
    match m {
        AclMatch::Any => "any".to_string(),
        AclMatch::Host(ip) => format!("host {}", ip),
        AclMatch::Network { addr, wildcard } => format!("{} {}", addr, wildcard),
        AclMatch::Prefix(net) => {
            let wc = invert_prefix(net);
            format!("{} {}", net.addr(), wc)
        }
    }
}

fn render_protocol(proto: &AclProtocol) -> String {
    match proto {
        AclProtocol::Ip     => "ip".to_string(),
        AclProtocol::Tcp    => "tcp".to_string(),
        AclProtocol::Udp    => "udp".to_string(),
        AclProtocol::Icmp   => "icmp".to_string(),
        AclProtocol::Esp    => "esp".to_string(),
        AclProtocol::Ahp    => "ahp".to_string(),
        AclProtocol::Number(n) => n.to_string(),
    }
}

fn render_port(port: &AclPort) -> String {
    match port {
        AclPort::Eq(p)      => format!("eq {}", p),
        AclPort::Ne(p)      => format!("ne {}", p),
        AclPort::Lt(p)      => format!("lt {}", p),
        AclPort::Gt(p)      => format!("gt {}", p),
        AclPort::Range(a,b) => format!("range {} {}", a, b),
    }
}

fn format_source_acl_entry(entry: &AclEntry) -> String {
    let action = match entry.action { AclAction::Permit => "permit", AclAction::Deny => "deny" };
    format!("{} {:?} → {:?}", action, entry.src, entry.dst)
}

/// Только для IPv4 — см. известное ограничение в VRP-рендерере (тот же
/// паттерн). AclMatch::Prefix сейчас не создаётся парсером IOS (он всегда
/// строит Network{addr,wildcard} или Host/Any), так что эта ветка не
/// достигается в текущем пайплайне, но типобезопасность должна сохраняться
/// для будущего IPv6/CIDR-based парсинга.
fn invert_prefix(net: &ipnet::IpNet) -> std::net::Ipv4Addr {
    let bits: u32 = if net.prefix_len() == 0 { u32::MAX } else {
        u32::MAX >> net.prefix_len()
    };
    std::net::Ipv4Addr::from(bits)
}
