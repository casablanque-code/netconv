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

    if bgp.log_neighbor_changes {
        out.push(" peer log-change".to_string());
        report.add_approximate(
            "bgp.log",
            "bgp log-neighbor-changes",
            "peer log-change",
            "VRP: 'peer log-change' вместо 'bgp log-neighbor-changes'",
        );
    }

    // Peer groups — сначала объявляем группы, потом привязываем соседей
    for pg in &bgp.peer_groups {
        render_bgp_peer_group(pg, out, report);
    }

    // Neighbors
    for neighbor in &bgp.neighbors {
        render_bgp_neighbor(neighbor, out, report);
    }

    // Глобальные networks → ipv4-family unicast
    let has_global_nets = !bgp.networks.is_empty();
    let has_global_redist = !bgp.redistribute.is_empty();

    // Собираем все address-family блоки
    // Если есть глобальные network/redistribute — добавляем их в ipv4 unicast
    if has_global_nets || has_global_redist {
        out.push(" #".to_string());
        out.push(" ipv4-family unicast".to_string());

        for net in &bgp.networks {
            let mask = prefix_len_to_mask(net.prefix_len());
            let cmd = format!("  network {} {}", net.addr(), mask);
            out.push(cmd.clone());
            report.add_approximate(
                "bgp.network",
                &format!("network {} mask {}", net.addr(), mask),
                &cmd,
                "VRP: network внутри ipv4-family unicast",
            );
        }

        for redist in &bgp.redistribute {
            render_bgp_redistribute(redist, out, report);
        }

        // Активируем всех соседей в ipv4 unicast по умолчанию
        for neighbor in &bgp.neighbors {
            out.push(format!("  peer {} enable", neighbor.address));
        }

        out.push(" #".to_string());
    }

    // Явные address-family блоки
    for af in &bgp.address_families {
        render_bgp_address_family(af, bgp, out, report);
    }

    out.push("#".to_string());
    out.push(String::new());
}

fn render_bgp_peer_group(pg: &BgpPeerGroup, out: &mut Vec<String>, report: &mut ConversionReport) {
    // Cisco: neighbor PEER-GROUP peer-group
    // VRP:   peer-group PEER-GROUP
    out.push(format!(" peer-group {}", pg.name));
    report.add_approximate(
        "bgp.peer_group",
        &format!("neighbor {} peer-group", pg.name),
        &format!("peer-group {}", pg.name),
        "VRP: 'peer-group NAME' вместо 'neighbor NAME peer-group'",
    );

    if let Some(asn) = pg.remote_as {
        out.push(format!(" peer-group {} as-number {}", pg.name, asn));
        report.add_approximate(
            "bgp.peer_group.as",
            &format!("neighbor {} remote-as {}", pg.name, asn),
            &format!("peer-group {} as-number {}", pg.name, asn),
            "VRP: peer-group remote-as задаётся через 'peer-group NAME as-number'",
        );
    }

    if let Some(src) = &pg.update_source {
        out.push(format!(" peer-group {} connect-interface {}", pg.name, src));
        report.add_approximate(
            "bgp.peer_group.source",
            &format!("neighbor {} update-source {}", pg.name, src),
            &format!("peer-group {} connect-interface {}", pg.name, src),
            "VRP: 'connect-interface' вместо 'update-source'",
        );
    }
}

fn render_bgp_neighbor(neighbor: &BgpNeighbor, out: &mut Vec<String>, report: &mut ConversionReport) {
    let addr = &neighbor.address;

    if neighbor.remote_as > 0 {
        out.push(format!(" peer {} as-number {}", addr, neighbor.remote_as));
        report.add_approximate(
            "bgp.neighbor",
            &format!("neighbor {} remote-as {}", addr, neighbor.remote_as),
            &format!("peer {} as-number {}", addr, neighbor.remote_as),
            "VRP BGP: 'peer' вместо 'neighbor', 'as-number' вместо 'remote-as'",
        );
    }

    if let Some(pg) = &neighbor.peer_group {
        out.push(format!(" peer {} group {}", addr, pg));
        report.add_approximate(
            "bgp.neighbor.peer_group",
            &format!("neighbor {} peer-group {}", addr, pg),
            &format!("peer {} group {}", addr, pg),
            "VRP: 'peer X group NAME' вместо 'neighbor X peer-group NAME'",
        );
    }

    if let Some(desc) = &neighbor.description {
        out.push(format!(" peer {} description {}", addr, desc));
        report.add_exact(
            "bgp.neighbor.description",
            &format!("neighbor {} description {}", addr, desc),
            &format!("peer {} description {}", addr, desc),
        );
    }

    if let Some(src) = &neighbor.update_source {
        out.push(format!(" peer {} connect-interface {}", addr, src));
        report.add_approximate(
            "bgp.update_source",
            &format!("neighbor {} update-source {}", addr, src),
            &format!("peer {} connect-interface {}", addr, src),
            "VRP: 'connect-interface' вместо 'update-source'",
        );
    }

    if neighbor.next_hop_self {
        out.push(format!(" peer {} next-hop-local", addr));
        report.add_approximate(
            "bgp.next_hop_self",
            &format!("neighbor {} next-hop-self", addr),
            &format!("peer {} next-hop-local", addr),
            "VRP: 'next-hop-local' вместо 'next-hop-self'",
        );
    }

    if neighbor.send_community {
        out.push(format!(" peer {} advertise-community", addr));
        report.add_approximate(
            "bgp.send_community",
            &format!("neighbor {} send-community", addr),
            &format!("peer {} advertise-community", addr),
            "VRP: 'advertise-community' вместо 'send-community'",
        );
    }

    if neighbor.remove_private_as {
        out.push(format!(" peer {} public-as-only", addr));
        report.add_approximate(
            "bgp.remove_private_as",
            &format!("neighbor {} remove-private-as", addr),
            &format!("peer {} public-as-only", addr),
            "VRP: 'public-as-only' вместо 'remove-private-as'",
        );
    }

    if neighbor.shutdown {
        out.push(format!(" peer {} ignore", addr));
        report.add_approximate(
            "bgp.shutdown",
            &format!("neighbor {} shutdown", addr),
            &format!("peer {} ignore", addr),
            "VRP: 'peer X ignore' для administrative shutdown",
        );
    }

    if let Some(rm) = &neighbor.route_map_in {
        out.push(format!(" peer {} route-policy {} import", addr, rm));
        report.add_approximate(
            "bgp.route_map",
            &format!("neighbor {} route-map {} in", addr, rm),
            &format!("peer {} route-policy {} import", addr, rm),
            "VRP: route-map → route-policy, in/out → import/export",
        );
    }

    if let Some(rm) = &neighbor.route_map_out {
        out.push(format!(" peer {} route-policy {} export", addr, rm));
        report.add_approximate(
            "bgp.route_map",
            &format!("neighbor {} route-map {} out", addr, rm),
            &format!("peer {} route-policy {} export", addr, rm),
            "VRP: route-map → route-policy, in/out → import/export",
        );
    }

    if let Some(pl) = &neighbor.prefix_list_in {
        out.push(format!(" peer {} ip-prefix {} import", addr, pl));
        report.add_approximate(
            "bgp.prefix_list",
            &format!("neighbor {} prefix-list {} in", addr, pl),
            &format!("peer {} ip-prefix {} import", addr, pl),
            "VRP: ip-prefix вместо prefix-list, import/export вместо in/out",
        );
    }

    if let Some(pl) = &neighbor.prefix_list_out {
        out.push(format!(" peer {} ip-prefix {} export", addr, pl));
        report.add_approximate(
            "bgp.prefix_list",
            &format!("neighbor {} prefix-list {} out", addr, pl),
            &format!("peer {} ip-prefix {} export", addr, pl),
            "VRP: ip-prefix вместо prefix-list, import/export вместо in/out",
        );
    }

    if neighbor.soft_reconfiguration {
        // VRP не требует soft-reconfiguration inbound — route refresh поддерживается нативно
        out.push(format!(" # neighbor {} soft-reconfiguration inbound — не нужно на VRP (route-refresh нативный)", addr));
        report.add_approximate(
            "bgp.soft_reconfiguration",
            &format!("neighbor {} soft-reconfiguration inbound", addr),
            "# not needed",
            "VRP поддерживает Route Refresh (RFC 2918) нативно — soft-reconfiguration не нужен",
        );
    }
}

fn render_bgp_address_family(
    af: &BgpAddressFamily,
    _bgp: &BgpConfig,
    out: &mut Vec<String>,
    report: &mut ConversionReport,
) {
    // Cisco: address-family ipv4 unicast
    // VRP:   ipv4-family unicast  (внутри bgp блока)
    let (vrp_family, ios_family) = match (&af.afi, &af.safi) {
        (BgpAfi::Ipv4, BgpSafi::Unicast)   => ("ipv4-family unicast",   "address-family ipv4 unicast"),
        (BgpAfi::Ipv4, BgpSafi::Multicast)  => ("ipv4-family multicast", "address-family ipv4 multicast"),
        (BgpAfi::Ipv4, BgpSafi::Labeled)    => ("ipv4-family labeled-unicast", "address-family ipv4 labeled-unicast"),
        (BgpAfi::Ipv6, BgpSafi::Unicast)    => ("ipv6-family unicast",   "address-family ipv6 unicast"),
        (BgpAfi::Vpnv4, _)                  => ("vpnv4-family",          "address-family vpnv4"),
        (BgpAfi::L2vpn, BgpSafi::Evpn)      => ("l2vpn-family evpn",     "address-family l2vpn evpn"),
        _                                    => ("ipv4-family unicast",   "address-family ipv4"),
    };

    out.push(" #".to_string());
    out.push(format!(" {}", vrp_family));

    report.add_approximate(
        "bgp.address_family",
        ios_family,
        vrp_family,
        "VRP: ipv4-family вместо address-family ipv4; синтаксис блока совпадает",
    );

    // networks
    for net in &af.networks {
        let mask = prefix_len_to_mask(net.prefix_len());
        out.push(format!("  network {} {}", net.addr(), mask));
        report.add_exact(
            "bgp.af.network",
            &format!("network {} mask {}", net.addr(), mask),
            &format!("network {} {}", net.addr(), mask),
        );
    }

    // redistribute
    for redist in &af.redistribute {
        render_bgp_redistribute(redist, out, report);
    }

    // aggregate-address
    for agg in &af.aggregate_addresses {
        let mask = prefix_len_to_mask(agg.prefix.prefix_len());
        let so = if agg.summary_only { " detail-suppressed" } else { "" };
        out.push(format!("  aggregate {} {}{}", agg.prefix.addr(), mask, so));
        report.add_approximate(
            "bgp.aggregate",
            &format!("aggregate-address {} {}{}", agg.prefix.addr(), mask,
                if agg.summary_only { " summary-only" } else { "" }),
            &format!("aggregate {} {}{}", agg.prefix.addr(), mask, so),
            "VRP: 'aggregate' вместо 'aggregate-address', 'detail-suppressed' вместо 'summary-only'",
        );
    }

    // neighbor activate — на VRP это peer enable внутри af блока
    for addr in &af.activated_neighbors {
        out.push(format!("  peer {} enable", addr));
        report.add_approximate(
            "bgp.af.activate",
            &format!("neighbor {} activate", addr),
            &format!("peer {} enable", addr),
            "VRP: 'peer X enable' внутри af блока вместо 'neighbor X activate'",
        );
    }

    // per-af neighbor настройки
    for n in &af.neighbor_settings {
        if n.next_hop_self {
            out.push(format!("  peer {} next-hop-local", n.address));
        }
        if let Some(rm) = &n.route_map_in {
            out.push(format!("  peer {} route-policy {} import", n.address, rm));
        }
        if let Some(rm) = &n.route_map_out {
            out.push(format!("  peer {} route-policy {} export", n.address, rm));
        }
        if n.soft_reconfiguration {
            out.push(format!("  # peer {} soft-reconfiguration — не нужно на VRP", n.address));
        }
        if n.default_originate {
            out.push(format!("  peer {} default-route-advertise", n.address));
            report.add_approximate(
                "bgp.af.default_originate",
                &format!("neighbor {} default-originate", n.address),
                &format!("peer {} default-route-advertise", n.address),
                "VRP: 'default-route-advertise' вместо 'default-originate'",
            );
        }
    }

    out.push(" #".to_string());
}

fn render_bgp_redistribute(redist: &OspfRedistribute, out: &mut Vec<String>, report: &mut ConversionReport) {
    let (vrp_src, ios_src) = match &redist.source {
        RedistributeSource::Connected => ("direct",   "connected"),
        RedistributeSource::Static    => ("static",   "static"),
        RedistributeSource::Rip       => ("rip",      "rip"),
        RedistributeSource::Bgp(_)    => return, // BGP в BGP не редистрибутят
        RedistributeSource::Eigrp(_)  => {
            report.add_manual(
                "bgp.redistribute.eigrp",
                "redistribute eigrp",
                "EIGRP не поддерживается на VRP",
                None,
            );
            return;
        }
    };

    let cmd = format!("  import-route {}", vrp_src);
    out.push(cmd.clone());
    report.add_approximate(
        "bgp.redistribute",
        &format!("redistribute {}", ios_src),
        &cmd,
        "VRP BGP: import-route вместо redistribute",
    );
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
