use netconv_core::ir::*;
use netconv_core::report::ConversionReport;

pub fn render_interfaces(cfg: &NetworkConfig, out: &mut Vec<String>, report: &mut ConversionReport) {
    for iface in &cfg.interfaces {
        render_interface(iface, out, report);
    }
}

fn render_interface(iface: &Interface, out: &mut Vec<String>, report: &mut ConversionReport) {
    let vrp_name = ios_to_vrp_ifname(&iface.name);

    out.push("#".to_string());
    out.push(format!("interface {}", vrp_name));

    let src_block = format!("interface {}", iface.name.original);

    // description — 1:1
    if let Some(desc) = &iface.description {
        out.push(format!(" description {}", desc));
        report.add_exact("interface.description", &src_block, &format!("description {}", desc));
    }

    // shutdown / undo shutdown
    if iface.shutdown {
        out.push(" shutdown".to_string());
        report.add_exact("interface.shutdown", &src_block, "shutdown");
    } else {
        out.push(" undo shutdown".to_string());
        report.add_exact("interface.shutdown", &src_block, "undo shutdown");
    }

    // MTU
    if let Some(mtu) = iface.mtu {
        out.push(format!(" mtu {}", mtu));
        report.add_exact("interface.mtu", &src_block, &format!("mtu {}", mtu));
    }

    // Speed
    if let Some(speed) = &iface.speed {
        match speed {
            InterfaceSpeed::Auto => {
                out.push(" speed auto".to_string());
                report.add_exact("interface.speed", &src_block, "speed auto");
            }
            InterfaceSpeed::Mbps(mbps) => {
                out.push(format!(" speed {}", mbps));
                report.add_exact("interface.speed", &src_block, &format!("speed {}", mbps));
            }
        }
    }

    // Duplex
    if let Some(duplex) = &iface.duplex {
        let d = match duplex {
            Duplex::Full => "full",
            Duplex::Half => "half",
            Duplex::Auto => "auto",
        };
        out.push(format!(" duplex {}", d));
        report.add_exact("interface.duplex", &src_block, &format!("duplex {}", d));
    }

    // IP addresses
    for (i, addr) in iface.addresses.iter().enumerate() {
        let mask = prefix_len_to_mask(addr.prefix.prefix_len());
        if i == 0 && !addr.secondary {
            out.push(format!(" ip address {} {}", addr.prefix.addr(), mask));
            report.add_exact(
                "interface.ip",
                &format!("ip address {} ({})", addr.prefix, iface.name.original),
                &format!("ip address {} {}", addr.prefix.addr(), mask),
            );
        } else {
            // VRP: secondary через sub-interface или просто второй ip address
            out.push(format!(" ip address {} {} sub", addr.prefix.addr(), mask));
            report.add_approximate(
                "interface.ip.secondary",
                &format!("ip address {} secondary", addr.prefix),
                &format!("ip address {} {} sub", addr.prefix.addr(), mask),
                "VRP использует ключевое слово 'sub' для secondary адресов",
            );
        }
    }

    // DHCP relay (helper-address → dhcp-snooping или relay)
    for helper in &iface.helper_addresses {
        // Cisco: ip helper-address 10.0.0.254
        // VRP:   dhcp relay server-ip 10.0.0.254  (в контексте интерфейса)
        out.push(format!(" dhcp relay server-ip {}", helper));
        report.add_approximate(
            "interface.helper",
            &format!("ip helper-address {} on {}", helper, iface.name.original),
            &format!("dhcp relay server-ip {}", helper),
            "На VRP также требуется 'dhcp enable' глобально и 'dhcp select relay' на интерфейсе",
        );
    }

    // L2 / switchport
    if let Some(l2) = &iface.l2 {
        render_l2(l2, out, report, &src_block);
    }

    // ACL in/out
    // Cisco: ip access-group NAME in
    // VRP:   traffic-filter inbound acl name NAME
    if let Some(acl_in) = &iface.acl_in {
        out.push(format!(" traffic-filter inbound acl name {}", acl_in));
        report.add_approximate(
            "interface.acl",
            &format!("ip access-group {} in", acl_in),
            &format!("traffic-filter inbound acl name {}", acl_in),
            "VRP использует traffic-filter вместо access-group; проверь совместимость нумерации ACL",
        );
    }
    if let Some(acl_out) = &iface.acl_out {
        out.push(format!(" traffic-filter outbound acl name {}", acl_out));
        report.add_approximate(
            "interface.acl",
            &format!("ip access-group {} out", acl_out),
            &format!("traffic-filter outbound acl name {}", acl_out),
            "VRP использует traffic-filter вместо access-group",
        );
    }

    // NAT direction — только маркер, сам NAT рендерится отдельно
    if let Some(nat_dir) = &iface.nat_direction {
        match nat_dir {
            NatDirection::Inside => {
                out.push(" # nat: inside (настраивается через 'nat outbound' на этом интерфейсе)".to_string());
            }
            NatDirection::Outside => {
                out.push(" # nat: outside".to_string());
            }
        }
    }

    // OSPF на интерфейсе
    if let Some(ospf) = &iface.ospf {
        render_interface_ospf(ospf, out, report, &src_block);
    }

    // HSRP → VRRP (Approximate)
    for hsrp in &iface.hsrp {
        render_hsrp_as_vrrp(hsrp, out, report, &src_block);
    }

    out.push(String::new());
}

fn render_l2(l2: &L2Config, out: &mut Vec<String>, report: &mut ConversionReport, ctx: &str) {
    match l2.mode {
        L2Mode::Access => {
            out.push(" port link-type access".to_string());
            report.add_exact("interface.l2", ctx, "port link-type access");
            if let Some(vlan) = l2.access_vlan {
                out.push(format!(" port default vlan {}", vlan));
                report.add_approximate(
                    "interface.l2.vlan",
                    &format!("switchport access vlan {}", vlan),
                    &format!("port default vlan {}", vlan),
                    "VRP использует 'port default vlan' вместо 'switchport access vlan'",
                );
            }
        }
        L2Mode::Trunk => {
            out.push(" port link-type trunk".to_string());
            report.add_exact("interface.l2", ctx, "port link-type trunk");

            if let Some(native) = l2.trunk_native {
                out.push(format!(" port trunk pvid vlan {}", native));
                report.add_approximate(
                    "interface.l2.native",
                    &format!("switchport trunk native vlan {}", native),
                    &format!("port trunk pvid vlan {}", native),
                    "VRP использует 'port trunk pvid vlan' для native VLAN",
                );
            }

            if let Some(allowed) = &l2.trunk_allowed {
                let vlan_list = allowed.iter()
                    .map(|v| v.to_string())
                    .collect::<Vec<_>>()
                    .join(" ");
                out.push(format!(" port trunk allow-pass vlan {}", vlan_list));
                report.add_approximate(
                    "interface.l2.trunk_allowed",
                    "switchport trunk allowed vlan ...",
                    &format!("port trunk allow-pass vlan {}", vlan_list),
                    "VRP использует 'port trunk allow-pass vlan'",
                );
            }
        }
    }
}

fn render_interface_ospf(ospf: &InterfaceOspf, out: &mut Vec<String>, report: &mut ConversionReport, ctx: &str) {
    // VRP: ospf <pid> area <area> — команда на интерфейсе
    // (это альтернатива network в router ospf, VRP поддерживает оба способа)
    let area_str = ospf_area_to_string(&ospf.area);
    out.push(format!(" ospf {} area {}", ospf.process_id, area_str));
    report.add_exact("ospf.interface", ctx, &format!("ospf {} area {}", ospf.process_id, area_str));

    if let Some(cost) = ospf.cost {
        out.push(format!(" ospf cost {}", cost));
        report.add_exact("ospf.cost", ctx, &format!("ospf cost {}", cost));
    }

    if let Some(priority) = ospf.priority {
        out.push(format!(" ospf dr-priority {}", priority));
        report.add_approximate(
            "ospf.priority",
            &format!("ip ospf priority {}", priority),
            &format!("ospf dr-priority {}", priority),
            "VRP использует 'ospf dr-priority' вместо 'ip ospf priority'",
        );
    }

    if let Some(timers) = &ospf.timers {
        out.push(format!(" ospf timer hello {}", timers.hello_interval));
        out.push(format!(" ospf timer dead {}", timers.dead_interval));
        report.add_exact("ospf.timers", ctx, "ospf timer hello/dead");
    }

    if let Some(auth) = &ospf.auth {
        render_ospf_auth_interface(auth, out, report, ctx);
    }

    if ospf.passive {
        out.push(" ospf silent-interface enable".to_string());
        report.add_approximate(
            "ospf.passive",
            "ip ospf passive",
            "ospf silent-interface enable",
            "Проверь: на VRP passive можно задать глобально или на интерфейсе",
        );
    }
}

fn render_ospf_auth_interface(auth: &OspfAuth, out: &mut Vec<String>, report: &mut ConversionReport, _ctx: &str) {
    match auth {
        OspfAuth::Simple(key) => {
            out.push(format!(" ospf authentication-mode simple plain {}", key));
            report.add_approximate(
                "ospf.auth",
                "ip ospf authentication / ip ospf authentication-key",
                "ospf authentication-mode simple plain",
                "Simple text auth — рассмотри замену на MD5 или HMAC-SHA256",
            );
        }
        OspfAuth::Md5 { key_id, key } => {
            out.push(format!(" ospf authentication-mode md5 {} plain {}", key_id, key));
            report.add_exact(
                "ospf.auth",
                &format!("ip ospf authentication message-digest (key {})", key_id),
                &format!("ospf authentication-mode md5 {} plain {}", key_id, key),
            );
        }
    }
}

fn render_hsrp_as_vrrp(hsrp: &HsrpGroup, out: &mut Vec<String>, report: &mut ConversionReport, ctx: &str) {
    // HSRP → VRRP: Approximate
    // Cisco: standby 1 ip 10.0.0.1 / standby 1 priority 110 / standby 1 preempt
    // VRP:   vrrp vrid 1 virtual-ip 10.0.0.1
    //        vrrp vrid 1 priority 110
    //        vrrp vrid 1 preempt-mode timer delay 0

    out.push(format!(" vrrp vrid {} virtual-ip {}", hsrp.group_id, hsrp.virtual_ip));

    let note = "HSRP → VRRP: протоколы несовместимы бинарно. \
                Preempt поведение по умолчанию отличается. \
                HSRP использует MAC 0000.0c07.acXX, VRRP — 0000.5e00.01XX. \
                Убедись что все узлы переведены одновременно.";

    report.add_approximate(
        "hsrp_to_vrrp",
        &format!("standby {} ip {} (on {})", hsrp.group_id, hsrp.virtual_ip, ctx),
        &format!("vrrp vrid {} virtual-ip {}", hsrp.group_id, hsrp.virtual_ip),
        note,
    );

    if let Some(priority) = hsrp.priority {
        out.push(format!(" vrrp vrid {} priority {}", hsrp.group_id, priority));
        report.add_approximate(
            "hsrp_to_vrrp.priority",
            &format!("standby {} priority {}", hsrp.group_id, priority),
            &format!("vrrp vrid {} priority {}", hsrp.group_id, priority),
            "Default priority у HSRP = 100, у VRRP = 100 — совпадает",
        );
    }

    if hsrp.preempt {
        let delay = hsrp.preempt_delay.unwrap_or(0);
        out.push(format!(" vrrp vrid {} preempt-mode timer delay {}", hsrp.group_id, delay));
        report.add_approximate(
            "hsrp_to_vrrp.preempt",
            &format!("standby {} preempt", hsrp.group_id),
            &format!("vrrp vrid {} preempt-mode timer delay {}", hsrp.group_id, delay),
            "Preempt включён по умолчанию у VRRP на VRP — явная команда избыточна но безопасна",
        );
    }

    if let Some(timers) = &hsrp.timers {
        // HSRP таймеры в ms → VRRP в сотых долях секунды
        let hello_cs = timers.hello_ms / 10;
        out.push(format!(" vrrp vrid {} timer advertise centisecond {}", hsrp.group_id, hello_cs));
        report.add_approximate(
            "hsrp_to_vrrp.timers",
            &format!("standby {} timers {}ms {}ms", hsrp.group_id, timers.hello_ms, timers.hold_ms),
            &format!("vrrp vrid {} timer advertise centisecond {}", hsrp.group_id, hello_cs),
            "VRP VRRP таймеры в сотых долях секунды; hold-time не задаётся явно (3x advertise)",
        );
    }

    // Track — HSRP track → VRRP track (через NQA или BFD на VRP)
    for track in &hsrp.track {
        out.push(format!(
            " # MANUAL: standby {} track {} decrement {} → \
              на VRP используй 'vrrp vrid {} track' с NQA/BFD вместо track object",
            hsrp.group_id, track.object, track.decrement, hsrp.group_id
        ));
        report.add_manual(
            "hsrp_to_vrrp.track",
            &format!("standby {} track {} decrement {}", hsrp.group_id, track.object, track.decrement),
            "HSRP track object не имеет прямого аналога в VRP VRRP",
            Some("Используй VRP NQA + 'vrrp vrid N track nqa admin test1' или BFD для аналогичного поведения"),
        );
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Cisco IOS имя → Huawei VRP имя
/// GigabitEthernet0/0 → GigabitEthernet0/0/0  (VRP требует 3 уровня для физических)
/// Loopback0 → LoopBack0  (регистр)
/// Vlan10 → Vlanif10
pub fn ios_to_vrp_ifname(name: &InterfaceName) -> String {
    match &name.kind {
        InterfaceKind::GigabitEthernet => {
            // Если у Cisco 2 цифры (0/0), добавляем слот: 0/0/0
            let id = normalize_vrp_port_id(&name.id);
            format!("GigabitEthernet{}", id)
        }
        InterfaceKind::TenGigabitEthernet => {
            let id = normalize_vrp_port_id(&name.id);
            format!("XGigabitEthernet{}", id)
        }
        InterfaceKind::FastEthernet => {
            let id = normalize_vrp_port_id(&name.id);
            // FastEthernet нет в большинстве Huawei — рендерим как Ethernet
            format!("Ethernet{}", id)
        }
        InterfaceKind::Loopback => {
            format!("LoopBack{}", name.id)
        }
        InterfaceKind::Vlan => {
            // Cisco: interface Vlan10 → VRP: interface Vlanif10
            format!("Vlanif{}", name.id)
        }
        InterfaceKind::Tunnel => {
            format!("Tunnel{}", name.id)
        }
        InterfaceKind::Management => {
            format!("MEth0/0/0")
        }
        InterfaceKind::Serial => {
            format!("Serial{}", name.id)
        }
        _ => name.original.clone(),
    }
}

/// "0/0" → "0/0/0", "0/0/0" → "0/0/0" (уже правильно)
fn normalize_vrp_port_id(id: &str) -> String {
    let parts: Vec<&str> = id.split('/').collect();
    match parts.len() {
        1 => format!("0/0/{}", parts[0]),
        2 => format!("0/{}/{}", parts[0], parts[1]),
        _ => id.to_string(),
    }
}

pub fn ospf_area_to_string(area: &OspfArea) -> String {
    match area {
        OspfArea::Backbone => "0".to_string(),
        OspfArea::Normal(n) => n.to_string(),
        OspfArea::IpFormat(ip) => ip.to_string(),
    }
}

fn prefix_len_to_mask(prefix_len: u8) -> std::net::Ipv4Addr {
    let bits: u32 = if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - prefix_len)
    };
    std::net::Ipv4Addr::from(bits)
}
