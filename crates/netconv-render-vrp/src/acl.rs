use netconv_core::ir::*;
use netconv_core::report::ConversionReport;

pub fn render_acls(cfg: &NetworkConfig, out: &mut Vec<String>, report: &mut ConversionReport) {
    for acl in &cfg.acls {
        render_acl(acl, out, report);
    }
}

fn render_acl(acl: &Acl, out: &mut Vec<String>, report: &mut ConversionReport) {
    // VRP ACL нумерация:
    // 2000-2999: basic (standard)
    // 3000-3999: advanced (extended)
    // named ACL: acl name <name> [basic|advance]

    let (acl_header, _vrp_type) = match &acl.name {
        AclName::Named(name) => {
            let t = match acl.acl_type {
                AclType::Standard => "basic",
                AclType::Extended => "advance",
            };
            (format!("acl name {} {}", name, t), t)
        }
        AclName::Numbered(n) => {
            let (vrp_num, t) = match acl.acl_type {
                AclType::Standard => (2000 + (n % 1000), "basic"),
                AclType::Extended => (3000 + (n % 1000), "advance"),
            };

            let src_name = format!("access-list {}", n);
            let note = format!(
                "Cisco numbered ACL {} → VRP ACL {}. \
                 Standard (1-99,1300-1999) → basic (2000-2999). \
                 Extended (100-199,2000-2699) → advance (3000-3999).",
                n, vrp_num
            );
            report.add_approximate("acl.numbered", &src_name, &format!("acl {}", vrp_num), &note);

            (format!("acl {}", vrp_num), t)
        }
    };

    out.push("#".to_string());
    out.push(acl_header.clone());

    for entry in &acl.entries {
        if let Some(remark) = &entry.remark {
            out.push(format!(" description {}", remark));
            continue;
        }

        let rule = render_acl_entry(entry, &acl.acl_type);
        out.push(format!(" {}", rule));

        let src = format_ios_acl_entry(entry);
        report.add_approximate(
            "acl.entry",
            &src,
            &rule,
            "VRP ACL синтаксис: 'rule' вместо sequence в начале, permit/deny → те же слова",
        );
    }

    out.push(String::new());
}

fn render_acl_entry(entry: &AclEntry, acl_type: &AclType) -> String {
    let seq = entry.sequence.unwrap_or(10);
    let action = match entry.action {
        AclAction::Permit => "permit",
        AclAction::Deny   => "deny",
    };

    match acl_type {
        AclType::Standard => {
            // VRP basic ACL: rule <seq> permit|deny [source <addr> <wc>]
            let src = render_acl_match_vrp(&entry.src);
            format!("rule {} {} source {}", seq, action, src)
        }
        AclType::Extended => {
            // VRP advance ACL: rule <seq> permit|deny <proto> source <...> [sport] dest <...> [dport]
            let proto = entry.protocol.as_ref().map(render_protocol_vrp).unwrap_or_else(|| "ip".to_string());
            let src = render_acl_match_vrp(&entry.src);
            let src_port = entry.src_port.as_ref()
                .map(|p| format!(" source-port {}", render_port_vrp(p)))
                .unwrap_or_default();

            let dst = entry.dst.as_ref()
                .map(|d| format!(" destination {}", render_acl_match_vrp(d)))
                .unwrap_or_else(|| " destination any".to_string());

            let dst_port = entry.dst_port.as_ref()
                .map(|p| format!(" destination-port {}", render_port_vrp(p)))
                .unwrap_or_default();

            let tcp_flag = if entry.established { " tcp-flag ack" } else { "" };
            let log_str  = if entry.log { " logging" } else { "" };

            format!("rule {} {} {} source {}{}{}{}{}{}", seq, action, proto, src, src_port, dst, dst_port, tcp_flag, log_str)
        }
    }
}

fn render_acl_match_vrp(m: &AclMatch) -> String {
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

fn render_protocol_vrp(proto: &AclProtocol) -> String {
    match proto {
        AclProtocol::Ip     => "ip".to_string(),
        AclProtocol::Tcp    => "tcp".to_string(),
        AclProtocol::Udp    => "udp".to_string(),
        AclProtocol::Icmp   => "icmp".to_string(),
        AclProtocol::Esp    => "esp".to_string(),
        AclProtocol::Ahp    => "ah".to_string(),  // VRP использует 'ah' вместо 'ahp'
        AclProtocol::Number(n) => n.to_string(),
    }
}

fn render_port_vrp(port: &AclPort) -> String {
    match port {
        AclPort::Eq(p)      => format!("eq {}", p),
        AclPort::Ne(p)      => format!("neq {}", p),  // VRP: neq вместо ne
        AclPort::Lt(p)      => format!("lt {}", p),
        AclPort::Gt(p)      => format!("gt {}", p),
        AclPort::Range(a,b) => format!("range {} {}", a, b),
    }
}

fn format_ios_acl_entry(entry: &AclEntry) -> String {
    let action = match entry.action { AclAction::Permit => "permit", AclAction::Deny => "deny" };
    format!("{} {:?} → {:?}", action, entry.src, entry.dst)
}

fn invert_prefix(net: &ipnet::IpNet) -> std::net::Ipv4Addr {
    let bits: u32 = if net.prefix_len() == 0 { u32::MAX } else {
        u32::MAX >> net.prefix_len()
    };
    std::net::Ipv4Addr::from(bits)
}
