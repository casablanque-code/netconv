use std::net::IpAddr;
use ipnet::IpNet;
use netconv_core::ir::*;
use netconv_core::report::ConversionReport;
use crate::tree::{RawNode, RawTree};

/// Pass 2: обходим RawTree, заполняем IR.
/// Неизвестные ноды → UnknownBlock.
pub struct SemanticParser;

impl SemanticParser {
    pub fn analyze(&self, tree: &RawTree, report: &mut ConversionReport) -> NetworkConfig {
        let mut cfg = NetworkConfig::default();

        for node in &tree.nodes {
            self.dispatch_global(node, &mut cfg, report);
        }

        cfg
    }

    fn dispatch_global(&self, node: &RawNode, cfg: &mut NetworkConfig, report: &mut ConversionReport) {
        match node.keyword().to_lowercase().as_str() {
            "hostname" => {
                cfg.hostname = node.args().first().map(|s| s.to_string());
            }
            "ip" => self.handle_global_ip(node, cfg, report),
            "interface" => {
                if let Some(iface) = self.parse_interface(node, report) {
                    cfg.interfaces.push(iface);
                }
            }
            "router" => self.handle_router(node, cfg, report),
            "access-list" => self.handle_acl_global(node, cfg, report),
            "vlan" => {
                if let Some(v) = self.parse_vlan(node) {
                    cfg.vlans.push(v);
                }
            }
            "ntp" => self.handle_ntp(node, cfg),
            "snmp-server" => self.handle_snmp(node, cfg),
            "spanning-tree" => self.handle_spanning_tree(node, cfg),
            "username" => self.handle_username(node, cfg),
            "logging" => self.handle_logging(node, cfg),
            "line" => self.handle_line(node, cfg),
            "aaa" => self.handle_aaa_global(node, cfg),
            "banner" => {
                cfg.banner = Some(node.full().to_string());
            }
            // Платформо-специфичные — явно помечаем, не смешиваем с unknown
            "version" | "boot-start-marker" | "boot-end-marker" |
            "no" | "service" | "crypto" | "vtp" | "clock" |
            "system" | "errdisable" | "vstack" | "no-service" => {
                cfg.platform_specific.push(UnknownBlock {
                    line: node.line_num,
                    context: "global".to_string(),
                    raw: node.full().to_string(),
                });
            }
            _ => {
                cfg.unknown_blocks.push(UnknownBlock {
                    line: node.line_num,
                    context: "global".to_string(),
                    raw: node.full().to_string(),
                });
                report.add_unknown(node.full(), "global");
            }
        }
    }

    // -----------------------------------------------------------------------
    // Interface
    // -----------------------------------------------------------------------

    fn parse_interface(&self, node: &RawNode, report: &mut ConversionReport) -> Option<Interface> {
        let args = node.args();
        let name_str = args.join(" ");
        if name_str.is_empty() {
            return None;
        }

        let mut iface = Interface::default();
        iface.name = InterfaceName::parse(&name_str);

        for child in &node.children {
            self.parse_interface_child(child, &mut iface, report);
        }

        Some(iface)
    }

    fn parse_interface_child(
        &self,
        node: &RawNode,
        iface: &mut Interface,
        report: &mut ConversionReport,
    ) {
        let tokens: Vec<&str> = node.text.split_whitespace().collect();
        if tokens.is_empty() { return; }

        match tokens[0] {
            "description" => {
                iface.description = Some(tokens[1..].join(" "));
            }
            "ip" if tokens.len() >= 2 => match tokens[1] {
                "address" => {
                    if let Some(addr) = self.parse_ip_address(&tokens[2..]) {
                        let secondary = tokens.contains(&"secondary");
                        iface.addresses.push(IpAddress { prefix: addr, secondary });
                    }
                }
                "helper-address" => {
                    if let Some(ip) = tokens.get(2).and_then(|s| s.parse().ok()) {
                        iface.helper_addresses.push(ip);
                    }
                }
                "access-group" => {
                    if tokens.len() >= 4 {
                        match tokens[3] {
                            "in"  => iface.acl_in  = Some(tokens[2].to_string()),
                            "out" => iface.acl_out = Some(tokens[2].to_string()),
                            _ => {}
                        }
                    }
                }
                "nat" => {
                    iface.nat_direction = match tokens.get(2) {
                        Some(&"inside")  => Some(NatDirection::Inside),
                        Some(&"outside") => Some(NatDirection::Outside),
                        _ => None,
                    };
                }
                "ospf" => {
                    self.parse_interface_ospf_cmd(&tokens[2..], iface);
                }
                _ => self.unknown_iface_cmd(node, iface, report),
            },
            "no" if tokens.len() >= 2 => match tokens[1] {
                "shutdown"   => iface.shutdown = false,
                "ip address" => { /* no ip address — игнорируем */ }
                _ => { /* остальные no-команды — игнорируем тихо */ }
            },
            "shutdown" => iface.shutdown = true,
            "mtu" => {
                iface.mtu = tokens.get(1).and_then(|s| s.parse().ok());
            }
            "speed" => {
                iface.speed = tokens.get(1).map(|s| match *s {
                    "auto" => InterfaceSpeed::Auto,
                    n => InterfaceSpeed::Mbps(n.parse().unwrap_or(0)),
                });
            }
            "duplex" => {
                iface.duplex = tokens.get(1).map(|s| match *s {
                    "full" => Duplex::Full,
                    "half" => Duplex::Half,
                    _      => Duplex::Auto,
                });
            }
            "switchport" => {
                self.parse_switchport(&tokens[1..], iface);
            }
            "standby" => {
                if let Some(hsrp) = self.parse_hsrp(&tokens[1..]) {
                    let gid = hsrp.group_id;
                    if let Some(existing) = iface.hsrp.iter_mut().find(|h| h.group_id == gid) {
                        merge_hsrp(existing, hsrp);
                    } else {
                        iface.hsrp.push(hsrp);
                    }
                }
            }
            "storm-control" => {
                // storm-control broadcast level 5.00
                // storm-control multicast level 5.00
                let sc = iface.storm_control.get_or_insert(StormControl::default());
                if tokens.len() >= 4 && tokens[2] == "level" {
                    let level: f32 = tokens[3].parse().unwrap_or(100.0);
                    match tokens[1] {
                        "broadcast" => sc.broadcast_level = Some(level),
                        "multicast" => sc.multicast_level = Some(level),
                        "unicast"   => sc.unicast_level   = Some(level),
                        _ => {}
                    }
                }
            }
            "spanning-tree" => {
                // spanning-tree portfast
                // spanning-tree bpduguard enable
                // spanning-tree bpdufilter enable
                // spanning-tree guard root
                match tokens.get(1) {
                    Some(&"portfast")   => iface.stp.portfast   = true,
                    Some(&"bpduguard")  => iface.stp.bpduguard  = tokens.get(2) != Some(&"disable"),
                    Some(&"bpdufilter") => iface.stp.bpdufilter = tokens.get(2) != Some(&"disable"),
                    Some(&"guard") if tokens.get(2) == Some(&"root") => iface.stp.guard_root = true,
                    _ => {}
                }
            }
            _ => self.unknown_iface_cmd(node, iface, report),
        }
    }

    fn unknown_iface_cmd(&self, node: &RawNode, iface: &mut Interface, report: &mut ConversionReport) {
        let ctx = format!("interface {}", iface.name.original);
        report.add_unknown(node.full(), &ctx);
    }

    fn parse_ip_address(&self, tokens: &[&str]) -> Option<IpNet> {
        if tokens.is_empty() { return None; }

        // CIDR формат: "192.168.1.1/24"
        if tokens[0].contains('/') {
            return tokens[0].parse().ok();
        }

        // Классический формат: "192.168.1.1 255.255.255.0"
        if tokens.len() >= 2 {
            let ip: IpAddr = tokens[0].parse().ok()?;
            let mask: IpAddr = tokens[1].parse().ok()?;
            let prefix_len = mask_to_prefix_len(mask)?;
            return format!("{}/{}", ip, prefix_len).parse().ok();
        }

        None
    }

    fn parse_switchport(&self, tokens: &[&str], iface: &mut Interface) {
        match tokens.first() {
            Some(&"mode") => {
                let mode = match tokens.get(1) {
                    Some(&"access") => L2Mode::Access,
                    Some(&"trunk")  => L2Mode::Trunk,
                    _ => return,
                };
                let l2 = iface.l2.get_or_insert(L2Config {
                    mode: mode.clone(),
                    access_vlan: None,
                    trunk_allowed: None,
                    trunk_native: None,
                });
                l2.mode = mode;
            }
            Some(&"access") if tokens.get(1) == Some(&"vlan") => {
                let vlan = tokens.get(2).and_then(|s| s.parse().ok());
                let l2 = iface.l2.get_or_insert(L2Config {
                    mode: L2Mode::Access,
                    access_vlan: None,
                    trunk_allowed: None,
                    trunk_native: None,
                });
                l2.access_vlan = vlan;
            }
            Some(&"voice") if tokens.get(1) == Some(&"vlan") => {
                iface.voice_vlan = tokens.get(2).and_then(|s| s.parse().ok());
            }
            Some(&"trunk") => match tokens.get(1) {
                Some(&"allowed") if tokens.get(2) == Some(&"vlan") => {
                    let vlans = parse_vlan_list(tokens.get(3).unwrap_or(&""));
                    let l2 = iface.l2.get_or_insert(L2Config {
                        mode: L2Mode::Trunk,
                        access_vlan: None,
                        trunk_allowed: None,
                        trunk_native: None,
                    });
                    l2.trunk_allowed = Some(vlans);
                }
                Some(&"native") if tokens.get(2) == Some(&"vlan") => {
                    let vlan = tokens.get(3).and_then(|s| s.parse().ok());
                    let l2 = iface.l2.get_or_insert(L2Config {
                        mode: L2Mode::Trunk,
                        access_vlan: None,
                        trunk_allowed: None,
                        trunk_native: None,
                    });
                    l2.trunk_native = vlan;
                }
                _ => {}
            },
            _ => {}
        }
    }

    fn parse_interface_ospf_cmd(&self, tokens: &[&str], iface: &mut Interface) {
        // ip ospf <process-id> area <area>
        // ip ospf cost <n>
        // ip ospf priority <n>
        // ip ospf hello-interval <n>
        // ip ospf dead-interval <n>
        // ip ospf authentication message-digest
        // ip ospf message-digest-key <id> md5 <key>
        match tokens.first() {
            Some(&"cost") => {
                let cost = tokens.get(1).and_then(|s| s.parse().ok());
                iface.ospf.get_or_insert_with(|| default_iface_ospf()).cost = cost;
            }
            Some(&"priority") => {
                let p = tokens.get(1).and_then(|s| s.parse().ok());
                iface.ospf.get_or_insert_with(|| default_iface_ospf()).priority = p;
            }
            Some(&"hello-interval") => {
                let v: u32 = tokens.get(1).and_then(|s| s.parse().ok()).unwrap_or(10);
                let ospf = iface.ospf.get_or_insert_with(|| default_iface_ospf());
                ospf.timers.get_or_insert(OspfIfTimers { hello_interval: v, dead_interval: 40 })
                    .hello_interval = v;
            }
            Some(&"dead-interval") => {
                let v: u32 = tokens.get(1).and_then(|s| s.parse().ok()).unwrap_or(40);
                let ospf = iface.ospf.get_or_insert_with(|| default_iface_ospf());
                ospf.timers.get_or_insert(OspfIfTimers { hello_interval: 10, dead_interval: v })
                    .dead_interval = v;
            }
            Some(&"authentication") => {
                if tokens.get(1) == Some(&"message-digest") {
                    // Ключ будет добавлен отдельной командой message-digest-key
                    // пока помечаем что MD5 включена
                    let ospf = iface.ospf.get_or_insert_with(|| default_iface_ospf());
                    if ospf.auth.is_none() {
                        ospf.auth = Some(OspfAuth::Md5 { key_id: 1, key: String::new() });
                    }
                }
            }
            Some(&"message-digest-key") => {
                if let (Some(id), Some(key)) = (
                    tokens.get(1).and_then(|s| s.parse::<u8>().ok()),
                    tokens.get(3), // message-digest-key <id> md5 <key>
                ) {
                    let ospf = iface.ospf.get_or_insert_with(|| default_iface_ospf());
                    ospf.auth = Some(OspfAuth::Md5 { key_id: id, key: key.to_string() });
                }
            }
            Some(pid) if pid.parse::<u32>().is_ok() => {
                // ip ospf <process-id> area <area>
                let process_id = pid.parse().unwrap();
                let area = OspfArea::parse(tokens.get(2).unwrap_or(&"0"));
                let ospf = iface.ospf.get_or_insert_with(|| default_iface_ospf());
                ospf.process_id = process_id;
                ospf.area = area;
            }
            _ => {}
        }
    }

    fn parse_hsrp(&self, tokens: &[&str]) -> Option<HsrpGroup> {
        // standby <group> ip <vip>
        // standby <group> priority <n>
        // standby <group> preempt [delay minimum <n>]
        // standby <group> timers [msec] <hello> [msec] <hold>
        // standby <group> track <obj> decrement <n>

        let group_id: u16 = tokens.first()?.parse().ok()?;

        let mut hsrp = HsrpGroup {
            group_id,
            virtual_ip: "0.0.0.0".parse().unwrap(),
            priority: None,
            preempt: false,
            preempt_delay: None,
            timers: None,
            track: vec![],
        };

        match tokens.get(1) {
            Some(&"ip") => {
                hsrp.virtual_ip = tokens.get(2)?.parse().ok()?;
            }
            Some(&"priority") => {
                hsrp.priority = tokens.get(2).and_then(|s| s.parse().ok());
            }
            Some(&"preempt") => {
                hsrp.preempt = true;
                if tokens.get(2) == Some(&"delay") && tokens.get(3) == Some(&"minimum") {
                    hsrp.preempt_delay = tokens.get(4).and_then(|s| s.parse().ok());
                }
            }
            Some(&"timers") => {
                // standby <g> timers [msec] <hello> [msec] <hold>
                // упрощённый парсинг секундных таймеров
                let hello = tokens.get(2).and_then(|s| s.parse::<u32>().ok());
                let hold  = tokens.get(3).and_then(|s| s.parse::<u32>().ok());
                if let (Some(h), Some(d)) = (hello, hold) {
                    hsrp.timers = Some(HsrpTimers { hello_ms: h * 1000, hold_ms: d * 1000 });
                }
            }
            Some(&"track") => {
                if let (Some(obj), Some(dec)) = (
                    tokens.get(2).and_then(|s| s.parse().ok()),
                    tokens.get(4).and_then(|s| s.parse().ok()),
                ) {
                    hsrp.track.push(HsrpTrack { object: obj, decrement: dec });
                }
            }
            _ => {}
        }

        Some(hsrp)
    }

    // -----------------------------------------------------------------------
    // Global IP commands
    // -----------------------------------------------------------------------

    fn handle_global_ip(&self, node: &RawNode, cfg: &mut NetworkConfig, report: &mut ConversionReport) {
        let tokens: Vec<&str> = node.text.split_whitespace().collect();
        if tokens.len() < 2 { return; }

        match tokens[1] {
            "domain-name" | "domain" => {
                cfg.domain_name = tokens.get(2).map(|s| s.to_string());
            }
            "name-server" => {
                for s in &tokens[2..] {
                    if let Ok(ip) = s.parse() {
                        cfg.dns.push(ip);
                    }
                }
            }
            "default-gateway" => {
                // ip default-gateway 172.20.252.242
                // → ip route-static 0.0.0.0 0.0.0.0 <gw>
                if let Some(gw) = tokens.get(2).and_then(|s| s.parse().ok()) {
                    cfg.routing.static_routes.push(StaticRoute {
                        prefix: "0.0.0.0/0".parse().unwrap(),
                        next_hop: NextHop::Ip(gw),
                        distance: None,
                        tag: None,
                        name: Some("default-gateway".to_string()),
                        permanent: false,
                    });
                }
            }
            "ssh" => {
                // ip ssh version 2
                if tokens.get(2) == Some(&"version") {
                    let ver: u8 = tokens.get(3).and_then(|s| s.parse().ok()).unwrap_or(2);
                    cfg.ssh = Some(SshConfig { version: ver, timeout: None, retries: None });
                }
            }
            "http" => {
                // ip http server / ip http secure-server — платформо-специфично
                cfg.platform_specific.push(UnknownBlock {
                    line: node.line_num,
                    context: "global".to_string(),
                    raw: node.full().to_string(),
                });
            }
            "access-list" => {
                self.handle_named_acl(node, cfg, report);
            }
            "nat" => self.handle_nat(node, cfg, report),
            "route" => {
                if let Some(route) = self.parse_static_route(&tokens[2..]) {
                    cfg.routing.static_routes.push(route);
                }
            }
            _ => {
                cfg.unknown_blocks.push(UnknownBlock {
                    line: node.line_num,
                    context: "global".to_string(),
                    raw: node.full().to_string(),
                });
            }
        }
    }

    fn parse_static_route(&self, tokens: &[&str]) -> Option<StaticRoute> {
        if tokens.len() < 2 { return None; }

        // ip route <network> <mask> <next-hop> [distance] [name <n>] [permanent]
        let net_addr: IpAddr = tokens[0].parse().ok()?;
        let mask: IpAddr = tokens[1].parse().ok()?;
        let prefix_len = mask_to_prefix_len(mask)?;
        let prefix: IpNet = format!("{}/{}", net_addr, prefix_len).parse().ok()?;

        if tokens.len() < 3 { return None; }
        let nh_str = tokens[2];

        let next_hop = if nh_str.eq_ignore_ascii_case("Null0") {
            NextHop::Null0
        } else if let Ok(ip) = nh_str.parse::<IpAddr>() {
            NextHop::Ip(ip)
        } else {
            NextHop::Interface(nh_str.to_string())
        };

        let mut route = StaticRoute {
            prefix,
            next_hop,
            distance: None,
            tag: None,
            name: None,
            permanent: false,
        };

        let mut i = 3;
        while i < tokens.len() {
            match tokens[i] {
                "name" if i + 1 < tokens.len() => {
                    route.name = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                "permanent" => { route.permanent = true; i += 1; }
                "tag" if i + 1 < tokens.len() => {
                    route.tag = tokens.get(i + 1).and_then(|s| s.parse().ok());
                    i += 2;
                }
                n if n.parse::<u8>().is_ok() => {
                    route.distance = n.parse().ok();
                    i += 1;
                }
                _ => { i += 1; }
            }
        }

        Some(route)
    }

    // -----------------------------------------------------------------------
    // Router blocks
    // -----------------------------------------------------------------------

    fn handle_router(&self, node: &RawNode, cfg: &mut NetworkConfig, report: &mut ConversionReport) {
        let tokens: Vec<&str> = node.text.split_whitespace().collect();
        match tokens.get(1) {
            Some(&"ospf") => {
                let pid: u32 = tokens.get(2).and_then(|s| s.parse().ok()).unwrap_or(1);
                let process = self.parse_ospf_process(pid, node, report);
                cfg.routing.ospf.push(process);
            }
            Some(&"bgp") => {
                let asn: u32 = tokens.get(2).and_then(|s| s.parse().ok()).unwrap_or(65000);
                let bgp = self.parse_bgp(asn, node, report);
                cfg.routing.bgp = Some(bgp);
            }
            Some(&"eigrp") => {
                let asn: u32 = tokens.get(2).and_then(|s| s.parse().ok()).unwrap_or(1);
                let eigrp = self.parse_eigrp(asn, node, report);
                cfg.routing.eigrp.push(eigrp);
            }
            _ => {
                cfg.unknown_blocks.push(UnknownBlock {
                    line: node.line_num,
                    context: "global".to_string(),
                    raw: node.full().to_string(),
                });
                report.add_unknown(node.full(), "global");
            }
        }
    }

    fn parse_ospf_process(&self, pid: u32, node: &RawNode, report: &mut ConversionReport) -> OspfProcess {
        let mut process = OspfProcess {
            process_id: pid,
            router_id: None,
            areas: vec![],
            passive_interfaces: vec![],
            default_originate: None,
            redistribute: vec![],
            max_metric: false,
            auth: None,
            log_adjacency: false,
        };

        // area map: area_id → OspfAreaConfig
        let mut areas: std::collections::HashMap<String, OspfAreaConfig> = Default::default();

        for child in &node.children {
            let tokens: Vec<&str> = child.text.split_whitespace().collect();
            match tokens.first() {
                Some(&"router-id") => {
                    process.router_id = tokens.get(1).and_then(|s| s.parse().ok());
                }
                Some(&"network") => {
                    // network <addr> <wildcard> area <area>
                    if tokens.len() >= 5 && tokens[3] == "area" {
                        let addr: IpAddr = match tokens[1].parse() { Ok(v) => v, Err(_) => continue };
                        let wc: IpAddr   = match tokens[2].parse() { Ok(v) => v, Err(_) => continue };
                        let area_str = tokens[4];
                        let area = OspfArea::parse(area_str);
                        let prefix = wildcard_to_prefix(addr, wc);
                        let net = OspfNetwork { prefix, wildcard: true };

                        let key = area_str.to_string();
                        let entry = areas.entry(key).or_insert_with(|| OspfAreaConfig {
                            area: area.clone(),
                            networks: vec![],
                            area_type: OspfAreaType::Normal,
                            auth: None,
                        });
                        entry.networks.push(net);
                    }
                }
                Some(&"passive-interface") => {
                    if let Some(iface) = tokens.get(1) {
                        if *iface != "default" {
                            process.passive_interfaces.push(iface.to_string());
                        }
                    }
                }
                Some(&"area") => {
                    if tokens.len() >= 3 {
                        let area_str = tokens[1];
                        match tokens[2] {
                            "stub" => {
                                let entry = areas.entry(area_str.to_string()).or_insert_with(|| OspfAreaConfig {
                                    area: OspfArea::parse(area_str),
                                    networks: vec![],
                                    area_type: OspfAreaType::Normal,
                                    auth: None,
                                });
                                entry.area_type = if tokens.get(3) == Some(&"no-summary") {
                                    OspfAreaType::StubNoSummary
                                } else {
                                    OspfAreaType::Stub
                                };
                            }
                            "nssa" => {
                                let entry = areas.entry(area_str.to_string()).or_insert_with(|| OspfAreaConfig {
                                    area: OspfArea::parse(area_str),
                                    networks: vec![],
                                    area_type: OspfAreaType::Normal,
                                    auth: None,
                                });
                                entry.area_type = if tokens.get(3) == Some(&"no-summary") {
                                    OspfAreaType::NssaNoSummary
                                } else {
                                    OspfAreaType::Nssa
                                };
                            }
                            "authentication" => {
                                let auth = if tokens.get(3) == Some(&"message-digest") {
                                    OspfAuth::Md5 { key_id: 1, key: String::new() }
                                } else {
                                    OspfAuth::Simple(String::new())
                                };
                                let entry = areas.entry(area_str.to_string()).or_insert_with(|| OspfAreaConfig {
                                    area: OspfArea::parse(area_str),
                                    networks: vec![],
                                    area_type: OspfAreaType::Normal,
                                    auth: None,
                                });
                                entry.auth = Some(auth);
                            }
                            _ => {}
                        }
                    }
                }
                Some(&"default-information") => {
                    // default-information originate [always] [metric <n>] [metric-type <n>]
                    let always = tokens.contains(&"always");
                    let metric = tokens.iter().position(|&t| t == "metric")
                        .and_then(|i| tokens.get(i + 1))
                        .and_then(|s| s.parse().ok());
                    let metric_type = tokens.iter().position(|&t| t == "metric-type")
                        .and_then(|i| tokens.get(i + 1))
                        .and_then(|s| s.parse().ok());
                    process.default_originate = Some(OspfDefaultOriginate { always, metric, metric_type });
                }
                Some(&"redistribute") => {
                    if let Some(r) = self.parse_ospf_redistribute(&tokens[1..]) {
                        process.redistribute.push(r);
                    }
                }
                Some(&"max-metric") => {
                    process.max_metric = true;
                }
                Some(&"log-adjacency-changes") => {
                    process.log_adjacency = true;
                }
                _ => {
                    report.add_unknown(child.full(), &format!("router ospf {}", pid));
                }
            }
        }

        process.areas = areas.into_values().collect();
        process
    }

    fn parse_ospf_redistribute(&self, tokens: &[&str]) -> Option<OspfRedistribute> {
        let source = match tokens.first() {
            Some(&"connected") => RedistributeSource::Connected,
            Some(&"static")    => RedistributeSource::Static,
            Some(&"rip")       => RedistributeSource::Rip,
            Some(&"bgp")  => RedistributeSource::Bgp(tokens.get(1).and_then(|s| s.parse().ok()).unwrap_or(65000)),
            Some(&"eigrp") => RedistributeSource::Eigrp(tokens.get(1).and_then(|s| s.parse().ok()).unwrap_or(1)),
            _ => return None,
        };

        let subnets     = tokens.contains(&"subnets");
        let metric      = tokens.iter().position(|&t| t == "metric")
            .and_then(|i| tokens.get(i + 1)).and_then(|s| s.parse().ok());
        let metric_type = tokens.iter().position(|&t| t == "metric-type")
            .and_then(|i| tokens.get(i + 1)).and_then(|s| s.parse().ok());
        let tag         = tokens.iter().position(|&t| t == "tag")
            .and_then(|i| tokens.get(i + 1)).and_then(|s| s.parse().ok());
        let route_map   = tokens.iter().position(|&t| t == "route-map")
            .and_then(|i| tokens.get(i + 1)).map(|s| s.to_string());

        Some(OspfRedistribute { source, metric, metric_type, subnets, tag, route_map })
    }

    fn parse_bgp(&self, asn: u32, node: &RawNode, report: &mut ConversionReport) -> BgpConfig {
        let mut bgp = BgpConfig {
            asn,
            router_id: None,
            neighbors: vec![],
            peer_groups: vec![],
            networks: vec![],
            address_families: vec![],
            redistribute: vec![],
            log_neighbor_changes: false,
            bestpath: None,
        };

        for child in &node.children {
            let tokens: Vec<&str> = child.text.split_whitespace().collect();
            match tokens.first() {
                Some(&"bgp") => self.parse_bgp_global_cmd(&tokens[1..], &mut bgp),
                Some(&"neighbor") => {
                    self.parse_bgp_neighbor_cmd(&tokens[1..], &mut bgp.neighbors, &mut bgp.peer_groups);
                }
                Some(&"network") => {
                    if let Some(net) = self.parse_bgp_network(&tokens[1..]) {
                        bgp.networks.push(net);
                    }
                }
                Some(&"redistribute") => {
                    if let Some(r) = self.parse_ospf_redistribute(&tokens[1..]) {
                        bgp.redistribute.push(r);
                    }
                }
                Some(&"address-family") => {
                    // address-family ipv4 [unicast|multicast]
                    // address-family ipv6 [unicast]
                    // address-family vpnv4
                    if let Some(af) = self.parse_address_family(asn, child, report) {
                        bgp.address_families.push(af);
                    }
                }
                _ => {
                    report.add_unknown(child.full(), &format!("router bgp {}", asn));
                }
            }
        }

        bgp
    }

    fn parse_bgp_global_cmd(&self, tokens: &[&str], bgp: &mut BgpConfig) {
        match tokens.first() {
            Some(&"router-id") => {
                bgp.router_id = tokens.get(1).and_then(|s| s.parse().ok());
            }
            Some(&"log-neighbor-changes") => {
                bgp.log_neighbor_changes = true;
            }
            Some(&"bestpath") => {
                bgp.bestpath = Some(tokens[1..].join(" "));
            }
            _ => {}
        }
    }

    fn parse_bgp_neighbor_cmd(
        &self,
        tokens: &[&str],
        neighbors: &mut Vec<BgpNeighbor>,
        peer_groups: &mut Vec<BgpPeerGroup>,
    ) {
        if tokens.is_empty() { return; }

        let addr_str = tokens[0];

        // Определяем: IP адрес или имя peer-group
        let addr = if let Ok(ip) = addr_str.parse::<IpAddr>() {
            BgpNeighborAddr::Ip(ip)
        } else {
            // Имя peer-group
            BgpNeighborAddr::PeerGroup(addr_str.to_string())
        };

        // Команда: neighbor <addr> peer-group [name] — создаёт peer-group
        if tokens.get(1) == Some(&"peer-group") && tokens.len() == 2 {
            // neighbor PEER-GROUP-NAME peer-group — объявление группы
            if let BgpNeighborAddr::PeerGroup(ref name) = addr {
                if !peer_groups.iter().any(|pg| &pg.name == name) {
                    peer_groups.push(BgpPeerGroup {
                        name: name.clone(),
                        remote_as: None,
                        update_source: None,
                        next_hop_self: false,
                        route_map_in: None,
                        route_map_out: None,
                        send_community: false,
                    });
                }
            }
            return;
        }

        // Ищем или создаём neighbour запись
        let neighbor = match neighbors.iter_mut().find(|n| n.address == addr) {
            Some(n) => n,
            None => {
                neighbors.push(BgpNeighbor {
                    address: addr,
                    remote_as: 0,
                    description: None,
                    update_source: None,
                    next_hop_self: false,
                    password: None,
                    shutdown: false,
                    peer_group: None,
                    route_map_in: None,
                    route_map_out: None,
                    prefix_list_in: None,
                    prefix_list_out: None,
                    soft_reconfiguration: false,
                    send_community: false,
                    remove_private_as: false,
                    default_originate: false,
                    activate: false,
                });
                neighbors.last_mut().unwrap()
            }
        };

        self.apply_bgp_neighbor_attr(tokens, neighbor, peer_groups);
    }

    fn apply_bgp_neighbor_attr(
        &self,
        tokens: &[&str],
        neighbor: &mut BgpNeighbor,
        _peer_groups: &mut Vec<BgpPeerGroup>,
    ) {
        match tokens.get(1) {
            Some(&"remote-as") => {
                neighbor.remote_as = tokens.get(2).and_then(|s| s.parse().ok()).unwrap_or(0);
            }
            Some(&"description") => {
                neighbor.description = Some(tokens[2..].join(" "));
            }
            Some(&"update-source") => {
                neighbor.update_source = tokens.get(2).map(|s| s.to_string());
            }
            Some(&"next-hop-self") => { neighbor.next_hop_self = true; }
            Some(&"password") => {
                neighbor.password = tokens.get(3).map(|s| s.to_string()); // password 0|7 <key>
            }
            Some(&"shutdown") => { neighbor.shutdown = true; }
            Some(&"peer-group") => {
                // neighbor 1.2.3.4 peer-group MY-PEERS — привязка к группе
                neighbor.peer_group = tokens.get(2).map(|s| s.to_string());
            }
            Some(&"route-map") => {
                let name = tokens.get(2).map(|s| s.to_string());
                match tokens.get(3) {
                    Some(&"in")  => neighbor.route_map_in  = name,
                    Some(&"out") => neighbor.route_map_out = name,
                    _ => {}
                }
            }
            Some(&"prefix-list") => {
                let name = tokens.get(2).map(|s| s.to_string());
                match tokens.get(3) {
                    Some(&"in")  => neighbor.prefix_list_in  = name,
                    Some(&"out") => neighbor.prefix_list_out = name,
                    _ => {}
                }
            }
            Some(&"soft-reconfiguration") => { neighbor.soft_reconfiguration = true; }
            Some(&"send-community") => { neighbor.send_community = true; }
            Some(&"remove-private-as") => { neighbor.remove_private_as = true; }
            Some(&"default-originate") => { neighbor.default_originate = true; }
            Some(&"activate") => { neighbor.activate = true; }
            _ => {}
        }
    }

    fn parse_address_family(
        &self,
        asn: u32,
        node: &RawNode,
        report: &mut ConversionReport,
    ) -> Option<BgpAddressFamily> {
        // address-family ipv4 [unicast|multicast|labeled-unicast]
        // address-family ipv6 unicast
        // address-family vpnv4
        let tokens: Vec<&str> = node.text.split_whitespace().collect();

        let afi = match tokens.get(1) {
            Some(&"ipv4")   => BgpAfi::Ipv4,
            Some(&"ipv6")   => BgpAfi::Ipv6,
            Some(&"vpnv4")  => BgpAfi::Vpnv4,
            Some(&"l2vpn")  => BgpAfi::L2vpn,
            _ => BgpAfi::Ipv4, // default
        };

        let safi = match tokens.get(2) {
            Some(&"multicast")       => BgpSafi::Multicast,
            Some(&"labeled-unicast") => BgpSafi::Labeled,
            Some(&"evpn")            => BgpSafi::Evpn,
            _                        => BgpSafi::Unicast,
        };

        let mut af = BgpAddressFamily {
            afi,
            safi,
            networks: vec![],
            redistribute: vec![],
            activated_neighbors: vec![],
            deactivated_neighbors: vec![],
            neighbor_settings: vec![],
            default_information: false,
            aggregate_addresses: vec![],
        };

        for child in &node.children {
            let ct: Vec<&str> = child.text.split_whitespace().collect();
            match ct.first() {
                Some(&"network") => {
                    if let Some(net) = self.parse_bgp_network(&ct[1..]) {
                        af.networks.push(net);
                    }
                }
                Some(&"redistribute") => {
                    if let Some(r) = self.parse_ospf_redistribute(&ct[1..]) {
                        af.redistribute.push(r);
                    }
                }
                Some(&"neighbor") => {
                    if ct.len() < 3 { continue; }
                    let addr = if let Ok(ip) = ct[1].parse::<IpAddr>() {
                        BgpNeighborAddr::Ip(ip)
                    } else {
                        BgpNeighborAddr::PeerGroup(ct[1].to_string())
                    };

                    match ct.get(2) {
                        Some(&"activate") => {
                            af.activated_neighbors.push(addr);
                        }
                        _ if ct.get(1) == Some(&"no") && ct.get(3) == Some(&"activate") => {
                            af.deactivated_neighbors.push(addr);
                        }
                        _ => {
                            // Другие per-af neighbour настройки
                            // ct = ["neighbor", "10.0.0.3", "soft-reconfiguration", ...]
                            // apply_bgp_neighbor_attr ожидает [addr, attr, ...]
                            // поэтому передаём &ct[1..]
                            let existing = af.neighbor_settings.iter_mut()
                                .find(|n| n.address == addr);
                            if let Some(n) = existing {
                                self.apply_bgp_neighbor_attr(&ct[1..], n, &mut vec![]);
                            } else {
                                let mut n = BgpNeighbor {
                                    address: addr,
                                    remote_as: 0,
                                    description: None,
                                    update_source: None,
                                    next_hop_self: false,
                                    password: None,
                                    shutdown: false,
                                    peer_group: None,
                                    route_map_in: None,
                                    route_map_out: None,
                                    prefix_list_in: None,
                                    prefix_list_out: None,
                                    soft_reconfiguration: false,
                                    send_community: false,
                                    remove_private_as: false,
                                    default_originate: false,
                                    activate: false,
                                };
                                self.apply_bgp_neighbor_attr(&ct[1..], &mut n, &mut vec![]);
                                af.neighbor_settings.push(n);
                            }
                        }
                    }
                }
                Some(&"default-information") => {
                    af.default_information = true;
                }
                Some(&"aggregate-address") => {
                    if let Some(agg) = self.parse_aggregate_address(&ct[1..]) {
                        af.aggregate_addresses.push(agg);
                    }
                }
                Some(&"exit-address-family") => break,
                _ => {
                    report.add_unknown(child.full(), &format!("router bgp {} address-family", asn));
                }
            }
        }

        Some(af)
    }

    fn parse_aggregate_address(&self, tokens: &[&str]) -> Option<BgpAggregate> {
        // aggregate-address <prefix/len> [summary-only] [as-set]
        // aggregate-address <addr> <mask> [summary-only] [as-set]
        if tokens.is_empty() { return None; }

        let prefix = if tokens[0].contains('/') {
            tokens[0].parse().ok()?
        } else if tokens.len() >= 2 {
            let addr: IpAddr = tokens[0].parse().ok()?;
            let mask: IpAddr = tokens[1].parse().ok()?;
            let plen = mask_to_prefix_len(mask)?;
            format!("{}/{}", addr, plen).parse().ok()?
        } else {
            return None;
        };

        Some(BgpAggregate {
            prefix,
            summary_only: tokens.contains(&"summary-only"),
            as_set: tokens.contains(&"as-set"),
        })
    }

    fn parse_bgp_network(&self, tokens: &[&str]) -> Option<IpNet> {
        // network <addr> mask <mask>
        // network <addr/prefix>
        if tokens.is_empty() { return None; }

        if tokens[0].contains('/') {
            return tokens[0].parse().ok();
        }

        if tokens.len() >= 3 && tokens[1] == "mask" {
            let addr: IpAddr = tokens[0].parse().ok()?;
            let mask: IpAddr = tokens[2].parse().ok()?;
            let plen = mask_to_prefix_len(mask)?;
            return format!("{}/{}", addr, plen).parse().ok();
        }

        None
    }

    fn parse_eigrp(&self, asn: u32, node: &RawNode, report: &mut ConversionReport) -> EigrpProcess {
        let mut eigrp = EigrpProcess {
            asn,
            networks: vec![],
            passive_interfaces: vec![],
            redistribute: vec![],
        };

        for child in &node.children {
            let tokens: Vec<&str> = child.text.split_whitespace().collect();
            match tokens.first() {
                Some(&"network") => {
                    if let Ok(addr) = tokens.get(1).unwrap_or(&"").parse::<IpAddr>() {
                        let wc: IpAddr = tokens.get(2)
                            .and_then(|s| s.parse().ok())
                            .unwrap_or("0.0.0.255".parse().unwrap());
                        let prefix = wildcard_to_prefix(addr, wc);
                        eigrp.networks.push(OspfNetwork { prefix, wildcard: true });
                    }
                }
                Some(&"passive-interface") => {
                    if let Some(i) = tokens.get(1) {
                        eigrp.passive_interfaces.push(i.to_string());
                    }
                }
                Some(&"redistribute") => {
                    if let Some(r) = self.parse_ospf_redistribute(&tokens[1..]) {
                        eigrp.redistribute.push(r);
                    }
                }
                _ => {
                    report.add_unknown(child.full(), &format!("router eigrp {}", asn));
                }
            }
        }

        eigrp
    }

    // -----------------------------------------------------------------------
    // ACL
    // -----------------------------------------------------------------------

    fn handle_acl_global(&self, node: &RawNode, cfg: &mut NetworkConfig, report: &mut ConversionReport) {
        // Два формата:
        // 1. ip access-list [standard|extended] <name>  (named, children = entries)
        // 2. access-list <number> permit/deny ...       (numbered, одна строка)

        let tokens: Vec<&str> = node.text.split_whitespace().collect();

        if tokens[0] == "access-list" {
            // numbered ACL — одна строка
            self.parse_numbered_acl_line(node, cfg, report);
            return;
        }

        // ip access-list standard/extended <name>
        if tokens.len() < 3 { return; }
        let acl_type = match tokens.get(if tokens[0] == "ip" { 2 } else { 1 }) {
            Some(&"standard") => AclType::Standard,
            Some(&"extended") => AclType::Extended,
            _ => AclType::Extended,
        };
        let name_idx = if tokens[0] == "ip" { 3 } else { 2 };
        let name_str = match tokens.get(name_idx) {
            Some(n) => n.to_string(),
            None => return,
        };

        let acl_name = if let Ok(n) = name_str.parse::<u32>() {
            AclName::Numbered(n)
        } else {
            AclName::Named(name_str)
        };

        let mut acl = Acl {
            name: acl_name,
            acl_type,
            entries: vec![],
        };

        for (seq, child) in node.children.iter().enumerate() {
            let ctokens: Vec<&str> = child.text.split_whitespace().collect();
            if let Some(entry) = self.parse_acl_entry(&ctokens, seq as u32 * 10 + 10) {
                acl.entries.push(entry);
            } else {
                report.add_unknown(child.full(), "ip access-list");
            }
        }

        cfg.acls.push(acl);
    }

    fn parse_numbered_acl_line(&self, node: &RawNode, cfg: &mut NetworkConfig, _report: &mut ConversionReport) {
        // access-list <number> [permit|deny] ...
        let tokens: Vec<&str> = node.text.split_whitespace().collect();
        if tokens.len() < 3 { return; }

        let number: u32 = match tokens[1].parse() { Ok(n) => n, Err(_) => return };
        let acl_type = if number < 100 { AclType::Standard } else { AclType::Extended };

        let entry = match self.parse_acl_entry(&tokens[2..], 10) {
            Some(e) => e,
            None => return,
        };

        // Находим или создаём ACL с этим номером
        if let Some(acl) = cfg.acls.iter_mut().find(|a| matches!(&a.name, AclName::Numbered(n) if *n == number)) {
            let next_seq = acl.entries.len() as u32 * 10 + 10;
            let mut e = entry;
            e.sequence = Some(next_seq);
            acl.entries.push(e);
        } else {
            let mut acl = Acl { name: AclName::Numbered(number), acl_type, entries: vec![] };
            acl.entries.push(entry);
            cfg.acls.push(acl);
        }
    }

    fn parse_acl_entry(&self, tokens: &[&str], default_seq: u32) -> Option<AclEntry> {
        if tokens.is_empty() { return None; }

        let mut pos = 0;

        // Опциональный sequence number
        let sequence = if tokens[pos].parse::<u32>().is_ok() {
            let s = tokens[pos].parse().ok();
            pos += 1;
            s
        } else {
            Some(default_seq)
        };

        // remark
        if tokens.get(pos) == Some(&"remark") {
            return Some(AclEntry {
                sequence,
                action: AclAction::Permit, // не важно для remark
                protocol: None,
                src: AclMatch::Any,
                dst: None,
                src_port: None,
                dst_port: None,
                established: false,
                log: false,
                remark: Some(tokens[pos + 1..].join(" ")),
            });
        }

        // action: permit | deny
        let action = match tokens.get(pos) {
            Some(&"permit") => AclAction::Permit,
            Some(&"deny")   => AclAction::Deny,
            _ => return None,
        };
        pos += 1;

        // protocol (только для extended)
        let protocol = match tokens.get(pos) {
            Some(&"ip")   => { pos += 1; Some(AclProtocol::Ip) }
            Some(&"tcp")  => { pos += 1; Some(AclProtocol::Tcp) }
            Some(&"udp")  => { pos += 1; Some(AclProtocol::Udp) }
            Some(&"icmp") => { pos += 1; Some(AclProtocol::Icmp) }
            Some(&"esp")  => { pos += 1; Some(AclProtocol::Esp) }
            Some(&"ahp")  => { pos += 1; Some(AclProtocol::Ahp) }
            Some(n) if n.parse::<u8>().is_ok() => {
                let p = n.parse().ok();
                pos += 1;
                p.map(AclProtocol::Number)
            }
            _ => None, // standard ACL
        };

        // src
        let (src, src_port, consumed) = self.parse_acl_match(&tokens[pos..]);
        pos += consumed;

        // dst (только для extended)
        let (dst, dst_port, consumed2) = if protocol.is_some() {
            let r = self.parse_acl_match(&tokens[pos..]);
            (Some(r.0), r.1, r.2)
        } else {
            (None, None, 0)
        };
        pos += consumed2;

        let established = tokens[pos..].contains(&"established");
        let log = tokens[pos..].contains(&"log");

        Some(AclEntry {
            sequence,
            action,
            protocol,
            src,
            dst,
            src_port,
            dst_port,
            established,
            log,
            remark: None,
        })
    }

    fn parse_acl_match(&self, tokens: &[&str]) -> (AclMatch, Option<AclPort>, usize) {
        if tokens.is_empty() {
            return (AclMatch::Any, None, 0);
        }

        match tokens[0] {
            "any" => (AclMatch::Any, None, 1),
            "host" => {
                let ip = tokens.get(1).and_then(|s| s.parse().ok()).unwrap_or("0.0.0.0".parse().unwrap());
                (AclMatch::Host(ip), None, 2)
            }
            addr_str => {
                let addr: IpAddr = match addr_str.parse() {
                    Ok(a) => a,
                    Err(_) => return (AclMatch::Any, None, 0),
                };
                if let Some(wc_str) = tokens.get(1) {
                    if let Ok(wc) = wc_str.parse::<IpAddr>() {
                        let m = AclMatch::Network { addr, wildcard: wc };
                        // порты после wildcard
                        let (port, pc) = self.parse_port(&tokens[2..]);
                        return (m, port, 2 + pc);
                    }
                }
                (AclMatch::Host(addr), None, 1)
            }
        }
    }

    fn parse_port(&self, tokens: &[&str]) -> (Option<AclPort>, usize) {
        match tokens.first() {
            Some(&"eq") => {
                let p = tokens.get(1).and_then(|s| port_name_to_num(s));
                (p.map(AclPort::Eq), 2)
            }
            Some(&"ne") => {
                let p = tokens.get(1).and_then(|s| port_name_to_num(s));
                (p.map(AclPort::Ne), 2)
            }
            Some(&"lt") => {
                let p = tokens.get(1).and_then(|s| port_name_to_num(s));
                (p.map(AclPort::Lt), 2)
            }
            Some(&"gt") => {
                let p = tokens.get(1).and_then(|s| port_name_to_num(s));
                (p.map(AclPort::Gt), 2)
            }
            Some(&"range") => {
                let p1 = tokens.get(1).and_then(|s| port_name_to_num(s));
                let p2 = tokens.get(2).and_then(|s| port_name_to_num(s));
                if let (Some(a), Some(b)) = (p1, p2) {
                    (Some(AclPort::Range(a, b)), 3)
                } else {
                    (None, 0)
                }
            }
            _ => (None, 0),
        }
    }

    // -----------------------------------------------------------------------
    // NAT
    // -----------------------------------------------------------------------

    fn handle_nat(&self, node: &RawNode, cfg: &mut NetworkConfig, report: &mut ConversionReport) {
        // ip nat inside source list <acl> {pool <name> | interface <if>} [overload]
        // ip nat inside source static <local> <global>
        // ip nat pool <name> <start> <end> prefix-length <n>
        let tokens: Vec<&str> = node.text.split_whitespace().collect();

        match tokens.get(2) {
            Some(&"source") => {
                match tokens.get(3) {
                    Some(&"list") => {
                        let acl = tokens.get(4).map(|s| s.to_string());
                        let overload = tokens.contains(&"overload");

                        let (pool, iface_overload) = if let Some(pool_pos) = tokens.iter().position(|&t| t == "pool") {
                            (tokens.get(pool_pos + 1).map(|s| NatPool {
                                name: s.to_string(),
                                start: "0.0.0.0".parse().unwrap(),
                                end: "0.0.0.0".parse().unwrap(),
                                prefix: None,
                                overload,
                            }), false)
                        } else if tokens.contains(&"interface") {
                            (None, true)
                        } else {
                            (None, false)
                        };

                        cfg.nat.push(NatRule {
                            rule_type: if overload || iface_overload { NatType::Overload } else { NatType::Dynamic },
                            acl,
                            pool,
                            interface_overload: iface_overload,
                            static_entry: None,
                        });
                    }
                    Some(&"static") => {
                        let local  = tokens.get(4).and_then(|s| s.parse().ok());
                        let global = tokens.get(5).and_then(|s| s.parse().ok());
                        if let (Some(l), Some(g)) = (local, global) {
                            cfg.nat.push(NatRule {
                                rule_type: NatType::Static,
                                acl: None,
                                pool: None,
                                interface_overload: false,
                                static_entry: Some(NatStaticEntry {
                                    local: l,
                                    global: g,
                                    local_port: None,
                                    global_port: None,
                                    protocol: None,
                                }),
                            });
                        }
                    }
                    _ => {
                        report.add_unknown(node.full(), "ip nat");
                    }
                }
            }
            _ => {
                report.add_unknown(node.full(), "ip nat");
            }
        }
    }

    // -----------------------------------------------------------------------
    // VLAN
    // -----------------------------------------------------------------------

    fn parse_vlan(&self, node: &RawNode) -> Option<Vlan> {
        let tokens: Vec<&str> = node.text.split_whitespace().collect();
        let id: u16 = tokens.get(1)?.parse().ok()?;

        let mut vlan = Vlan { id, name: None, active: true };

        for child in &node.children {
            let ct: Vec<&str> = child.text.split_whitespace().collect();
            match ct.first() {
                Some(&"name") => { vlan.name = ct.get(1).map(|s| s.to_string()); }
                Some(&"state") => { vlan.active = ct.get(1) != Some(&"suspend"); }
                _ => {}
            }
        }

        Some(vlan)
    }

    // -----------------------------------------------------------------------
    // NTP / SNMP
    // -----------------------------------------------------------------------

    fn handle_ntp(&self, node: &RawNode, cfg: &mut NetworkConfig) {
        let tokens: Vec<&str> = node.text.split_whitespace().collect();
        match tokens.get(1) {
            Some(&"server") => {
                if let Some(ip) = tokens.get(2).and_then(|s| s.parse().ok()) {
                    cfg.ntp.push(NtpServer {
                        address: ip,
                        prefer: tokens.contains(&"prefer"),
                        key: tokens.iter().position(|&t| t == "key")
                            .and_then(|i| tokens.get(i + 1))
                            .and_then(|s| s.parse().ok()),
                        source_interface: tokens.iter().position(|&t| t == "source")
                            .and_then(|i| tokens.get(i + 1))
                            .map(|s| s.to_string()),
                    });
                }
            }
            _ => {}
        }
    }

    fn handle_named_acl(&self, node: &RawNode, cfg: &mut NetworkConfig, report: &mut ConversionReport) {
        self.handle_acl_global(node, cfg, report);
    }

    fn handle_snmp(&self, node: &RawNode, cfg: &mut NetworkConfig) {
        let tokens: Vec<&str> = node.text.split_whitespace().collect();
        let snmp = cfg.snmp.get_or_insert(SnmpConfig {
            communities: vec![],
            location: None,
            contact: None,
            traps: vec![],
        });

        match tokens.get(1) {
            Some(&"community") => {
                if let Some(name) = tokens.get(2) {
                    let access = match tokens.get(3) {
                        Some(&"RW") | Some(&"rw") => SnmpAccess::Rw,
                        _ => SnmpAccess::Ro,
                    };
                    snmp.communities.push(SnmpCommunity {
                        name: name.to_string(),
                        access,
                        acl: tokens.get(4).map(|s| s.to_string()),
                    });
                }
            }
            Some(&"location") => {
                snmp.location = Some(tokens[2..].join(" "));
            }
            Some(&"contact") => {
                snmp.contact = Some(tokens[2..].join(" "));
            }
            _ => {}
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn default_iface_ospf() -> InterfaceOspf {
    InterfaceOspf {
        process_id: 1,
        area: OspfArea::Backbone,
        cost: None,
        priority: None,
        timers: None,
        auth: None,
        passive: false,
        network_type: None,
    }
}

fn merge_hsrp(existing: &mut HsrpGroup, new: HsrpGroup) {
    if new.virtual_ip != "0.0.0.0".parse::<IpAddr>().unwrap() {
        existing.virtual_ip = new.virtual_ip;
    }
    if new.priority.is_some() { existing.priority = new.priority; }
    if new.preempt { existing.preempt = true; }
    if new.preempt_delay.is_some() { existing.preempt_delay = new.preempt_delay; }
    if new.timers.is_some() { existing.timers = new.timers; }
    existing.track.extend(new.track);
}

fn mask_to_prefix_len(mask: IpAddr) -> Option<u8> {
    match mask {
        IpAddr::V4(m) => {
            let bits = u32::from(m);
            if bits == 0 { return Some(0); }
            // Проверяем что маска непрерывная
            let trailing = bits.trailing_zeros();
            if bits.wrapping_shl(trailing) == u32::MAX.wrapping_shl(32 - (32 - trailing)) {
                Some((32 - trailing) as u8)
            } else {
                // Нестрогая маска — считаем popcount
                Some(bits.count_ones() as u8)
            }
        }
        IpAddr::V6(_) => None,
    }
}

fn wildcard_to_prefix(addr: IpAddr, wildcard: IpAddr) -> IpNet {
    // Инвертируем wildcard → маска
    match (addr, wildcard) {
        (IpAddr::V4(a), IpAddr::V4(w)) => {
            let mask_bits = !u32::from(w);
            let prefix_len = mask_bits.leading_ones() as u8;
            let network = u32::from(a) & mask_bits;
            let net_addr = std::net::Ipv4Addr::from(network);
            format!("{}/{}", net_addr, prefix_len).parse()
                .unwrap_or_else(|_| "0.0.0.0/0".parse().unwrap())
        }
        _ => "0.0.0.0/0".parse().unwrap(),
    }
}

fn parse_vlan_list(s: &str) -> Vec<u16> {
    // "10,20,30-40,50"
    let mut result = vec![];
    for part in s.split(',') {
        if part.contains('-') {
            let bounds: Vec<&str> = part.splitn(2, '-').collect();
            if let (Ok(from), Ok(to)) = (bounds[0].parse::<u16>(), bounds[1].parse::<u16>()) {
                result.extend(from..=to);
            }
        } else if let Ok(n) = part.parse::<u16>() {
            result.push(n);
        }
    }
    result
}

fn port_name_to_num(s: &str) -> Option<u16> {
    // Основные well-known порты по имени
    match s {
        "ftp-data" => Some(20), "ftp" => Some(21), "ssh" => Some(22),
        "telnet" => Some(23), "smtp" => Some(25), "dns" => Some(53),
        "www" | "http" => Some(80), "pop3" => Some(110), "ntp" => Some(123),
        "https" => Some(443), "bgp" => Some(179), "ldap" => Some(389),
        "snmp" => Some(161), "syslog" => Some(514), "rdp" => Some(3389),
        _ => s.parse().ok(),
    }
}

// ---------------------------------------------------------------------------
// Новые глобальные обработчики
// ---------------------------------------------------------------------------

impl SemanticParser {
    pub fn handle_spanning_tree(&self, node: &RawNode, cfg: &mut NetworkConfig) {
        let tokens: Vec<&str> = node.text.split_whitespace().collect();
        let stp = cfg.stp.get_or_insert(GlobalStp {
            mode: StpMode::RapidPvst,
            loopguard: false,
            portfast_default: false,
            bpduguard_default: false,
            vlan_priorities: vec![],
        });

        match tokens.get(1) {
            Some(&"mode") => {
                stp.mode = match tokens.get(2) {
                    Some(&"rapid-pvst") => StpMode::RapidPvst,
                    Some(&"pvst")       => StpMode::Pvst,
                    Some(&"mst")        => StpMode::Mst,
                    _                   => StpMode::RapidPvst,
                };
            }
            Some(&"loopguard") => { stp.loopguard = true; }
            Some(&"portfast") if tokens.get(2) == Some(&"default") => {
                stp.portfast_default = true;
            }
            Some(&"portfast") if tokens.get(2) == Some(&"bpduguard") => {
                stp.bpduguard_default = true;
            }
            Some(&"vlan") => {
                // spanning-tree vlan 1,10-12,14-15,18,20 priority 12288
                if let Some(prio_pos) = tokens.iter().position(|&t| t == "priority") {
                    if let Some(priority) = tokens.get(prio_pos + 1).and_then(|s| s.parse().ok()) {
                        let vlans = parse_vlan_list(tokens.get(2).unwrap_or(&""));
                        stp.vlan_priorities.push(StpVlanPriority { vlans, priority });
                    }
                }
            }
            _ => {}
        }
    }

    pub fn handle_username(&self, node: &RawNode, cfg: &mut NetworkConfig) {
        // username root privilege 15 password 7 HASH
        // username root privilege 15 secret 5 HASH
        let tokens: Vec<&str> = node.text.split_whitespace().collect();
        if tokens.len() < 2 { return; }

        let name = tokens[1].to_string();
        let privilege: u8 = tokens.iter().position(|&t| t == "privilege")
            .and_then(|i| tokens.get(i + 1))
            .and_then(|s| s.parse().ok())
            .unwrap_or(1);

        let (pw_type, pw_hash) = if let Some(pos) = tokens.iter().position(|&t| t == "secret" || t == "password") {
            let type_indicator = tokens.get(pos + 1).copied().unwrap_or("0");
            let hash = tokens.get(pos + 2).copied().unwrap_or("").to_string();
            let pw_type = match (tokens[pos], type_indicator) {
                ("secret", "5") => PasswordType::Md5,
                ("secret", "9") => PasswordType::Scrypt,
                ("password", "7") => PasswordType::Type7,
                _ => PasswordType::Plaintext,
            };
            (pw_type, hash)
        } else {
            (PasswordType::Plaintext, String::new())
        };

        cfg.users.push(LocalUser { name, privilege, password_type: pw_type, password_hash: pw_hash });
    }

    pub fn handle_logging(&self, node: &RawNode, cfg: &mut NetworkConfig) {
        let tokens: Vec<&str> = node.text.split_whitespace().collect();
        let logging = cfg.logging.get_or_insert(LoggingConfig {
            buffered_size: None,
            console_level: None,
            hosts: vec![],
        });

        match tokens.get(1) {
            Some(&"buffered") => {
                logging.buffered_size = tokens.get(2).and_then(|s| s.parse().ok());
            }
            Some(&"console") => {
                logging.console_level = tokens.get(2).map(|s| s.to_string());
            }
            Some(host) => {
                if let Ok(ip) = host.parse() {
                    logging.hosts.push(ip);
                }
            }
            None => {}
        }
    }

    pub fn handle_line(&self, node: &RawNode, cfg: &mut NetworkConfig) {
        let tokens: Vec<&str> = node.text.split_whitespace().collect();
        // line vty 0 4 / line vty 5 15
        if tokens.get(1) != Some(&"vty") { return; }

        let vty = cfg.line_vty.get_or_insert(LineVty {
            exec_timeout_min: 10,
            exec_timeout_sec: 0,
            transport_input: vec![],
            logging_synchronous: false,
        });

        for child in &node.children {
            let ct: Vec<&str> = child.text.split_whitespace().collect();
            match ct.first() {
                Some(&"exec-timeout") => {
                    vty.exec_timeout_min = ct.get(1).and_then(|s| s.parse().ok()).unwrap_or(10);
                    vty.exec_timeout_sec = ct.get(2).and_then(|s| s.parse().ok()).unwrap_or(0);
                }
                Some(&"transport") if ct.get(1) == Some(&"input") => {
                    for proto in &ct[2..] {
                        vty.transport_input.push(proto.to_string());
                    }
                }
                Some(&"logging") if ct.get(1) == Some(&"synchronous") => {
                    vty.logging_synchronous = true;
                }
                _ => {}
            }
        }
    }

    pub fn handle_aaa_global(&self, node: &RawNode, cfg: &mut NetworkConfig) {
        let tokens: Vec<&str> = node.text.split_whitespace().collect();
        // aaa new-model — просто фиксируем факт
        if tokens.get(1) == Some(&"new-model") {
            cfg.aaa.get_or_insert(AaaConfig {
                new_model: true,
                authentication: vec![],
                authorization: vec![],
            }).new_model = true;
        }
        // aaa authentication/authorization — пропускаем в platform_specific
        // т.к. на VRP это принципиально другая подсистема
    }
}
