use netconv_core::ir::*;
use netconv_core::report::ConversionReport;
use crate::iface::ospf_area_to_string;

pub fn render_routing(cfg: &NetworkConfig, out: &mut Vec<String>, report: &mut ConversionReport) {
    render_static_routes(&cfg.routing.static_routes, out, report);
    for ospf in &cfg.routing.ospf {
        render_ospf(ospf, out, report);
    }
    if let Some(bgp) = &cfg.routing.bgp {
        render_bgp(bgp, out, report);
    }
    if !cfg.routing.eigrp.is_empty() {
        out.push(String::new());
        out.push("# ============================================================".to_string());
        out.push("# MANUAL: EIGRP не поддерживается на Huawei VRP.".to_string());
        out.push("# Замени на OSPF или BGP. Подсети EIGRP:".to_string());
        for eigrp in &cfg.routing.eigrp {
            for net in &eigrp.networks {
                out.push(format!("#   {}", net.prefix));
            }
            report.add_manual(
                "eigrp",
                &format!("router eigrp {}", eigrp.asn),
                "EIGRP — проприетарный протокол Cisco, не поддерживается на Huawei VRP",
                Some("Замени на OSPF (isis также поддерживается) или iBGP для внутренней маршрутизации"),
            );
        }
        out.push("# ============================================================".to_string());
    }
}

fn render_static_routes(routes: &[StaticRoute], out: &mut Vec<String>, report: &mut ConversionReport) {
    if routes.is_empty() { return; }

    out.push("#".to_string());

    for route in routes {
        let prefix = route.prefix;
        let mask = prefix_len_to_mask(prefix.prefix_len());

        let nh_str = match &route.next_hop {
            NextHop::Ip(ip)          => ip.to_string(),
            NextHop::Interface(i)    => i.clone(),
            NextHop::IpAndInterface(ip, _) => ip.to_string(),
            NextHop::Null0           => "NULL0".to_string(),
        };

        let distance_str = route.distance
            .map(|d| format!(" preference {}", d))
            .unwrap_or_default();

        let desc_str = route.name
            .as_ref()
            .map(|n| format!(" description {}", n))
            .unwrap_or_default();

        // Cisco: ip route 10.0.0.0 255.255.255.0 10.0.1.1 [distance]
        // VRP:   ip route-static 10.0.0.0 255.255.255.0 10.0.1.1 [preference N] [description X]
        let dst = format!("ip route-static {} {} {}{}{}", prefix.addr(), mask, nh_str, distance_str, desc_str);

        let src = format!("ip route {} {} {}{}",
            prefix.addr(), mask, nh_str,
            route.distance.map(|d| format!(" {}", d)).unwrap_or_default());

        out.push(dst.clone());
        report.add_approximate(
            "static_route",
            &src,
            &dst,
            "VRP использует 'ip route-static' и 'preference' вместо 'ip route' и AD",
        );
    }

    out.push(String::new());
}

fn render_ospf(ospf: &OspfProcess, out: &mut Vec<String>, report: &mut ConversionReport) {
    out.push("#".to_string());
    out.push(format!("ospf {} router-id {}", ospf.process_id,
        ospf.router_id.map(|r| r.to_string()).unwrap_or_else(|| "0.0.0.0".to_string())));

    let src_block = format!("router ospf {}", ospf.process_id);

    // router-id
    if let Some(rid) = ospf.router_id {
        report.add_exact(
            "ospf.router_id",
            &format!("router-id {}", rid),
            &format!("ospf {} router-id {}", ospf.process_id, rid),
        );
    }

    // log-adjacency-changes
    if ospf.log_adjacency {
        out.push(" log-peer-change".to_string());
        report.add_approximate(
            "ospf.log",
            "log-adjacency-changes",
            "log-peer-change",
            "VRP использует 'log-peer-change' для аналогичного поведения",
        );
    }

    // max-metric
    if ospf.max_metric {
        out.push(" stub-router on-startup advertise-forever".to_string());
        report.add_approximate(
            "ospf.max_metric",
            "max-metric router-lsa",
            "stub-router on-startup advertise-forever",
            "VRP аналог max-metric — stub-router; проверь параметры",
        );
    }

    // default-information originate
    if let Some(def) = &ospf.default_originate {
        let always_str = if def.always { " always" } else { "" };
        let mt_str = def.metric_type.map(|t| format!(" type {}", t)).unwrap_or_default();
        let mc_str = def.metric.map(|m| format!(" cost {}", m)).unwrap_or_default();
        let cmd = format!(" default-route-advertise{}{}{}", always_str, mc_str, mt_str);
        out.push(cmd.clone());
        report.add_approximate(
            "ospf.default_originate",
            &format!("default-information originate{}", always_str),
            &cmd.trim(),
            "VRP: 'default-route-advertise' — аналог; синтаксис параметров отличается",
        );
    }

    // redistribute
    for redist in &ospf.redistribute {
        render_ospf_redistribute(redist, ospf.process_id, out, report);
    }

    // Areas
    for area in &ospf.areas {
        render_ospf_area(area, out, report, &src_block);
    }

    // passive-interface
    // На VRP: silent-interface в контексте ospf процесса
    for iface in &ospf.passive_interfaces {
        out.push(format!(" silent-interface {}", iface));
        report.add_approximate(
            "ospf.passive",
            &format!("passive-interface {}", iface),
            &format!("silent-interface {}", iface),
            "VRP использует 'silent-interface' вместо 'passive-interface'",
        );
    }

    out.push("#".to_string());
    out.push(String::new());
}

fn render_ospf_area(area: &OspfAreaConfig, out: &mut Vec<String>, report: &mut ConversionReport, _ctx: &str) {
    let area_str = ospf_area_to_string(&area.area);

    out.push(format!(" area {}", area_str));

    // Area type
    match area.area_type {
        OspfAreaType::Normal => {}
        OspfAreaType::Stub => {
            out.push("  stub".to_string());
            report.add_exact("ospf.area_type", &format!("area {} stub", area_str), "stub");
        }
        OspfAreaType::StubNoSummary => {
            out.push("  stub no-summary".to_string());
            report.add_exact("ospf.area_type", &format!("area {} stub no-summary", area_str), "stub no-summary");
        }
        OspfAreaType::Nssa => {
            out.push("  nssa".to_string());
            report.add_exact("ospf.area_type", &format!("area {} nssa", area_str), "nssa");
        }
        OspfAreaType::NssaNoSummary => {
            out.push("  nssa no-summary".to_string());
            report.add_exact("ospf.area_type", &format!("area {} nssa no-summary", area_str), "nssa no-summary");
        }
    }

    // Area auth
    if let Some(auth) = &area.auth {
        match auth {
            OspfAuth::Simple(_) => {
                out.push("  authentication".to_string());
                report.add_approximate(
                    "ospf.area_auth",
                    &format!("area {} authentication", area_str),
                    "authentication",
                    "Simple area auth — рассмотри MD5",
                );
            }
            OspfAuth::Md5 { .. } => {
                out.push("  authentication-mode md5".to_string());
                report.add_exact(
                    "ospf.area_auth",
                    &format!("area {} authentication message-digest", area_str),
                    "authentication-mode md5",
                );
            }
        }
    }

    // Networks — в VRP network пишется внутри area блока
    for net in &area.networks {
        let mask = prefix_len_to_mask(net.prefix.prefix_len());
        let wc = invert_mask(mask);
        out.push(format!("  network {} {}", net.prefix.addr(), wc));
        report.add_exact(
            "ospf.network",
            &format!("network {} {} area {}", net.prefix.addr(), wc, area_str),
            &format!("network {} {} (inside area {})", net.prefix.addr(), wc, area_str),
        );
    }

    out.push(" #".to_string());
}

fn render_ospf_redistribute(redist: &OspfRedistribute, _pid: u32, out: &mut Vec<String>, report: &mut ConversionReport) {
    // Cisco: redistribute connected subnets
    // VRP:   import-route direct  (в контексте ospf)

    let (vrp_src, ios_src) = match &redist.source {
        RedistributeSource::Connected => ("direct", "connected"),
        RedistributeSource::Static    => ("static", "static"),
        RedistributeSource::Rip       => ("rip", "rip"),
        RedistributeSource::Bgp(asn)  => {
            out.push(format!(" import-route bgp {}", asn));
            report.add_approximate(
                "ospf.redistribute",
                &format!("redistribute bgp {} subnets", asn),
                &format!("import-route bgp {}", asn),
                "VRP: 'import-route' вместо 'redistribute'; BGP ASN синтаксис совпадает",
            );
            return;
        }
        RedistributeSource::Eigrp(_) => {
            report.add_manual(
                "ospf.redistribute.eigrp",
                "redistribute eigrp",
                "EIGRP не поддерживается на VRP — нечего редистрибутить",
                None,
            );
            return;
        }
    };

    let cost_str = redist.metric.map(|m| format!(" cost {}", m)).unwrap_or_default();
    let type_str = redist.metric_type.map(|t| format!(" type {}", t)).unwrap_or_default();
    let tag_str  = redist.tag.map(|t| format!(" tag {}", t)).unwrap_or_default();

    let cmd = format!(" import-route {}{}{}{}", vrp_src, cost_str, type_str, tag_str);
    out.push(cmd.clone());

    report.add_approximate(
        "ospf.redistribute",
        &format!("redistribute {} subnets", ios_src),
        cmd.trim(),
        "VRP: 'import-route' вместо 'redistribute'; 'subnets' не нужен",
    );
}

fn render_bgp(bgp: &BgpConfig, out: &mut Vec<String>, report: &mut ConversionReport) {
    out.push("#".to_string());
    out.push(format!("bgp {}", bgp.asn));

    if let Some(rid) = bgp.router_id {
        out.push(format!(" router-id {}", rid));
        report.add_exact("bgp.router_id", &format!("bgp router-id {}", rid), &format!("router-id {}", rid));
    }

    for neighbor in &bgp.neighbors {
        // Cisco: neighbor 1.2.3.4 remote-as 65001
        // VRP:   peer 1.2.3.4 as-number 65001
        out.push(format!(" peer {} as-number {}", neighbor.address, neighbor.remote_as));
        report.add_approximate(
            "bgp.neighbor",
            &format!("neighbor {} remote-as {}", neighbor.address, neighbor.remote_as),
            &format!("peer {} as-number {}", neighbor.address, neighbor.remote_as),
            "VRP BGP использует 'peer' вместо 'neighbor' и 'as-number' вместо 'remote-as'",
        );

        if let Some(desc) = &neighbor.description {
            out.push(format!(" peer {} description {}", neighbor.address, desc));
            report.add_exact(
                "bgp.neighbor.description",
                &format!("neighbor {} description {}", neighbor.address, desc),
                &format!("peer {} description {}", neighbor.address, desc),
            );
        }

        if let Some(src) = &neighbor.update_source {
            out.push(format!(" peer {} connect-interface {}", neighbor.address, src));
            report.add_approximate(
                "bgp.update_source",
                &format!("neighbor {} update-source {}", neighbor.address, src),
                &format!("peer {} connect-interface {}", neighbor.address, src),
                "VRP: 'connect-interface' вместо 'update-source'",
            );
        }

        if neighbor.next_hop_self {
            out.push(format!(" peer {} next-hop-local", neighbor.address));
            report.add_approximate(
                "bgp.next_hop_self",
                &format!("neighbor {} next-hop-self", neighbor.address),
                &format!("peer {} next-hop-local", neighbor.address),
                "VRP: 'next-hop-local' вместо 'next-hop-self'",
            );
        }

        if neighbor.shutdown {
            out.push(format!(" peer {} ignore", neighbor.address));
            report.add_approximate(
                "bgp.shutdown",
                &format!("neighbor {} shutdown", neighbor.address),
                &format!("peer {} ignore", neighbor.address),
                "VRP: 'peer X ignore' для administrative shutdown BGP соседа",
            );
        }
    }

    // IPv4 unicast address-family
    if !bgp.networks.is_empty() {
        out.push(" #".to_string());
        out.push(" ipv4-family unicast".to_string());
        for net in &bgp.networks {
            let mask = prefix_len_to_mask(net.prefix_len());
            out.push(format!("  network {} {}", net.addr(), mask));
            report.add_approximate(
                "bgp.network",
                &format!("network {} mask {}", net.addr(), mask),
                &format!("network {} {} (inside ipv4-family)", net.addr(), mask),
                "VRP: network команда находится внутри ipv4-family unicast блока",
            );
        }
        out.push(" #".to_string());
    }

    out.push("#".to_string());
    out.push(String::new());
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn prefix_len_to_mask(prefix_len: u8) -> std::net::Ipv4Addr {
    let bits: u32 = if prefix_len == 0 { 0 } else { u32::MAX << (32 - prefix_len) };
    std::net::Ipv4Addr::from(bits)
}

fn invert_mask(mask: std::net::Ipv4Addr) -> std::net::Ipv4Addr {
    let bits = u32::from(mask);
    std::net::Ipv4Addr::from(!bits)
}
