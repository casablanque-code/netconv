use netconv_core::ir::*;
use netconv_core::report::ConversionReport;
use crate::iface::ospf_area_str;

pub fn render_routing(cfg: &NetworkConfig, out: &mut Vec<String>, report: &mut ConversionReport) {
    render_static_routes(&cfg.routing.static_routes, out, report);
    for ospf in &cfg.routing.ospf {
        render_ospf(ospf, out, report);
    }
    if let Some(bgp) = &cfg.routing.bgp {
        render_bgp(bgp, out, report);
    }
    if !cfg.routing.eigrp.is_empty() {
        out.push("!".to_string());
        out.push("! MANUAL: EIGRP not supported on Eltex ESR.".to_string());
        out.push("!   Replace with OSPF or BGP.".to_string());
        for eigrp in &cfg.routing.eigrp {
            report.add_manual(
                "eigrp",
                &format!("router eigrp {}", eigrp.asn),
                "EIGRP — Cisco proprietary, not supported on Eltex ESR",
                Some("Use OSPF or BGP instead"),
            );
        }
    }
    // NAT
    render_nat(cfg, out, report);
}

fn render_static_routes(routes: &[StaticRoute], out: &mut Vec<String>, report: &mut ConversionReport) {
    if routes.is_empty() { return; }
    out.push("!".to_string());

    for route in routes {
        let nh_str = match &route.next_hop {
            NextHop::Ip(ip)                => ip.to_string(),
            NextHop::Interface(i)          => i.clone(),
            NextHop::IpAndInterface(ip, _) => ip.to_string(),
            NextHop::Null0                 => "null0".to_string(),
        };

        // ESR: ip route <prefix/len> <next-hop>
        // Cisco: ip route <net> <mask> <nh> [distance]
        let dst = format!("ip route {} {}", route.prefix, nh_str);
        out.push(dst.clone());

        let src = format!("ip route {} {}", route.prefix.addr(), nh_str);
        report.add_approximate(
            "static_route",
            &src,
            &dst,
            "ESR: ip route с CIDR нотацией. Administrative distance не поддерживается напрямую.",
        );

        if let Some(name) = &route.name {
            out.push(format!("! (was named: {})", name));
        }
    }
    out.push(String::new());
}

fn render_ospf(ospf: &OspfProcess, out: &mut Vec<String>, report: &mut ConversionReport) {
    out.push("!".to_string());
    // ESR: router ospf <instance-id>
    out.push(format!("router ospf {}", ospf.process_id));

    let src_block = format!("router ospf {}", ospf.process_id);

    if let Some(rid) = ospf.router_id {
        // ESR: ospf router-id <id>
        out.push(format!(" ospf router-id {}", rid));
        report.add_exact("ospf.router_id", &format!("router-id {}", rid),
            &format!("ospf router-id {}", rid));
    }

    if ospf.log_adjacency {
        out.push(" log-adjacency-changes".to_string());
        report.add_exact("ospf.log", "log-adjacency-changes", "log-adjacency-changes");
    }

    // Areas
    for area in &ospf.areas {
        render_ospf_area(area, out, report, &src_block);
    }

    // Passive interfaces
    for iface in &ospf.passive_interfaces {
        // ESR: passive-interface <if>
        out.push(format!(" passive-interface {}", iface));
        report.add_exact(
            "ospf.passive",
            &format!("passive-interface {}", iface),
            &format!("passive-interface {}", iface),
        );
    }

    // Default originate
    if let Some(def) = &ospf.default_originate {
        let always = if def.always { " always" } else { "" };
        out.push(format!(" default-information originate{}", always));
        report.add_exact(
            "ospf.default_originate",
            &format!("default-information originate{}", always),
            &format!("default-information originate{}", always),
        );
    }

    // Redistribute
    for redist in &ospf.redistribute {
        render_ospf_redistribute(redist, out, report);
    }

    out.push(" exit".to_string());
    out.push(String::new());
}

fn render_ospf_area(area: &OspfAreaConfig, out: &mut Vec<String>, report: &mut ConversionReport, _ctx: &str) {
    let area_str = ospf_area_str(&area.area);

    // Area networks
    for net in &area.networks {
        // ESR: area <id> range <prefix>  или network — зависит от версии
        // На новых ESR: network <prefix> area <id>
        out.push(format!(" network {} area {}", net.prefix, area_str));
        report.add_approximate(
            "ospf.network",
            &format!("network {} area {}", net.prefix.addr(), area_str),
            &format!("network {} area {}", net.prefix, area_str),
            "ESR: network с CIDR нотацией вместо wildcard маски",
        );
    }

    // Area type
    match area.area_type {
        OspfAreaType::Stub => {
            out.push(format!(" area {} stub", area_str));
            report.add_exact("ospf.area_type", &format!("area {} stub", area_str),
                &format!("area {} stub", area_str));
        }
        OspfAreaType::Nssa => {
            out.push(format!(" area {} nssa", area_str));
            report.add_exact("ospf.area_type", &format!("area {} nssa", area_str),
                &format!("area {} nssa", area_str));
        }
        _ => {}
    }

    // Auth
    if let Some(auth) = &area.auth {
        match auth {
            OspfAuth::Md5 { .. } => {
                out.push(format!(" area {} authentication message-digest", area_str));
                report.add_exact("ospf.auth", "area X authentication message-digest",
                    &format!("area {} authentication message-digest", area_str));
            }
            OspfAuth::Simple(_) => {
                out.push(format!(" area {} authentication", area_str));
                report.add_exact("ospf.auth", "area X authentication",
                    &format!("area {} authentication", area_str));
            }
        }
    }
}

fn render_ospf_redistribute(redist: &OspfRedistribute, out: &mut Vec<String>, report: &mut ConversionReport) {
    let (esr_src, ios_src) = match &redist.source {
        RedistributeSource::Connected => ("connected", "connected"),
        RedistributeSource::Static    => ("static",    "static"),
        RedistributeSource::Rip       => ("rip",       "rip"),
        RedistributeSource::Bgp(asn)  => {
            out.push(format!(" redistribute bgp {}", asn));
            report.add_exact("ospf.redistribute", &format!("redistribute bgp {}", asn),
                &format!("redistribute bgp {}", asn));
            return;
        }
        RedistributeSource::Eigrp(_) => {
            report.add_manual("ospf.redistribute.eigrp", "redistribute eigrp",
                "EIGRP not supported on ESR", None);
            return;
        }
    };

    let subnets = if redist.subnets { " subnets" } else { "" };
    out.push(format!(" redistribute {}{}", esr_src, subnets));
    report.add_approximate(
        "ospf.redistribute",
        &format!("redistribute {} subnets", ios_src),
        &format!("redistribute {}", esr_src),
        "ESR: redistribute синтаксис совпадает с Cisco",
    );
}

fn render_bgp(bgp: &BgpConfig, out: &mut Vec<String>, report: &mut ConversionReport) {
    out.push("!".to_string());
    out.push(format!("router bgp {}", bgp.asn));

    if let Some(rid) = bgp.router_id {
        out.push(format!(" bgp router-id {}", rid));
        report.add_exact("bgp.router_id", &format!("bgp router-id {}", rid),
            &format!("bgp router-id {}", rid));
    }

    for neighbor in &bgp.neighbors {
        let addr = &neighbor.address;
        if neighbor.remote_as > 0 {
            // ESR BGP синтаксис близок к Cisco
            out.push(format!(" neighbor {} remote-as {}", addr, neighbor.remote_as));
            report.add_exact(
                "bgp.neighbor",
                &format!("neighbor {} remote-as {}", addr, neighbor.remote_as),
                &format!("neighbor {} remote-as {}", addr, neighbor.remote_as),
            );
        }
        if let Some(desc) = &neighbor.description {
            out.push(format!(" neighbor {} description {}", addr, desc));
        }
        if let Some(src) = &neighbor.update_source {
            out.push(format!(" neighbor {} update-source {}", addr, src));
            report.add_exact("bgp.update_source",
                &format!("neighbor {} update-source {}", addr, src),
                &format!("neighbor {} update-source {}", addr, src));
        }
        if neighbor.next_hop_self {
            out.push(format!(" neighbor {} next-hop-self", addr));
            report.add_exact("bgp.next_hop_self",
                &format!("neighbor {} next-hop-self", addr),
                &format!("neighbor {} next-hop-self", addr));
        }
        if neighbor.shutdown {
            out.push(format!(" neighbor {} shutdown", addr));
        }
    }

    // address-family ipv4
    let all_networks: Vec<_> = bgp.networks.iter()
        .chain(bgp.address_families.iter()
            .filter(|af| af.afi == BgpAfi::Ipv4)
            .flat_map(|af| af.networks.iter()))
        .collect();

    if !all_networks.is_empty() {
        out.push(" address-family ipv4".to_string());
        for net in &all_networks {
            out.push(format!("  network {}", net));
            report.add_approximate(
                "bgp.network",
                &format!("network {} mask ...", net.addr()),
                &format!("network {} (inside address-family)", net),
                "ESR BGP: network с CIDR нотацией внутри address-family",
            );
        }
        // Активируем соседей
        for neighbor in &bgp.neighbors {
            out.push(format!("  neighbor {} activate", neighbor.address));
        }
        out.push("  exit-address-family".to_string());
    }

    out.push(" exit".to_string());
    out.push(String::new());
}

fn render_nat(cfg: &NetworkConfig, out: &mut Vec<String>, report: &mut ConversionReport) {
    if cfg.nat.is_empty() { return; }

    // Находим WAN интерфейс
    let wan_iface = cfg.interfaces.iter()
        .find(|i| i.nat_direction == Some(NatDirection::Outside));
    let wan_name = wan_iface.map(|i| crate::iface::ios_to_esr_ifname(&i.name));

    out.push("!".to_string());
    out.push("! NAT configuration".to_string());

    for rule in &cfg.nat {
        match &rule.rule_type {
            NatType::Overload => {
                // ESR NAT source — SNAT с overload
                // nat source
                //  ruleset WAN_NAT
                //   rule 10
                //    match source-address 0.0.0.0/0
                //    action source-nat interface
                //    enable
                //    exit
                //   exit
                //  exit
                let acl = rule.acl.as_deref().unwrap_or("ANY");
                out.push("nat source".to_string());
                out.push(format!(" ruleset SNAT_OVERLOAD"));
                out.push("  rule 10".to_string());
                if rule.interface_overload {
                    out.push("   action source-nat interface".to_string());
                    if let Some(wan) = &wan_name {
                        out.push(format!("   ! WAN interface: {}", wan));
                    }
                }
                out.push("   enable".to_string());
                out.push("   exit".to_string());
                out.push("  exit".to_string());
                out.push(" exit".to_string());

                report.add_approximate(
                    "nat.overload",
                    &format!("ip nat inside source list {} interface <WAN> overload", acl),
                    "nat source / ruleset SNAT_OVERLOAD / action source-nat interface",
                    "ESR NAT: иерархический синтаксис nat source → ruleset → rule. \
                     Проверь привязку к интерфейсам через security zones.",
                );
            }
            NatType::Static => {
                if let Some(entry) = &rule.static_entry {
                    // ESR static NAT:
                    // nat destination
                    //  ruleset DNAT_STATIC
                    //   rule 10
                    //    match destination-address <global>/32
                    //    action destination-nat <local>
                    //    enable
                    //    exit
                    out.push("nat destination".to_string());
                    out.push(" ruleset DNAT_STATIC".to_string());
                    out.push("  rule 10".to_string());
                    out.push(format!("   match destination-address {}/32", entry.global));
                    out.push(format!("   action destination-nat {}", entry.local));
                    out.push("   enable".to_string());
                    out.push("   exit".to_string());
                    out.push("  exit".to_string());
                    out.push(" exit".to_string());

                    report.add_approximate(
                        "nat.static",
                        &format!("ip nat inside source static {} {}", entry.local, entry.global),
                        "nat destination / ruleset / action destination-nat",
                        "ESR static NAT через nat destination ruleset. Синтаксис существенно отличается.",
                    );
                }
            }
            NatType::Dynamic => {
                out.push("! MANUAL: dynamic NAT — configure nat source ruleset manually".to_string());
                report.add_manual("nat.dynamic", "ip nat inside source list ... pool ...",
                    "ESR dynamic NAT requires manual ruleset configuration", None);
            }
        }
    }
    out.push(String::new());
}
